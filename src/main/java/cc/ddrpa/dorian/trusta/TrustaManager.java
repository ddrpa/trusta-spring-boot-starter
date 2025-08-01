package cc.ddrpa.dorian.trusta;

import cc.ddrpa.dorian.trusta.properties.TrustaProperties;
import cc.ddrpa.dorian.trusta.properties.TrustedIssuer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Central manager for Trusta JWT operations, including signing and verification.
 */
@Component
public class TrustaManager {

    private static final Logger logger = LoggerFactory.getLogger(TrustaManager.class);
    private final TrustaProperties trustaProperties;
    private final ObjectMapper objectMapper;
    private final String issuer;

    private final Map<String, JsonWebTokenVerify> verifyMap = new HashMap<>();
    private String publicKeySetAsJSONString;
    private JwtPublicKeySign jwtPublicKeySign;

    /**
     * Construct a TrustaManager with the given properties and object mapper.
     *
     * @param trustaProperties Trusta configuration properties
     * @param objectMapper     Jackson object mapper
     * @throws GeneralSecurityException if crypto fails
     * @throws IOException              if key loading fails
     */
    public TrustaManager(TrustaProperties trustaProperties, ObjectMapper objectMapper) throws GeneralSecurityException, IOException {
        this.trustaProperties = trustaProperties;
        this.issuer = trustaProperties.getIssuer();
        this.objectMapper = objectMapper;

        handlePrivateKeysetHandle();
        registerIssuers();
    }

    /**
     * 更新对端签发者公钥
     */
    public void updateIssuerPublicKey() {
        logger.info("Updating issuer public keys");
        verifyMap.values().forEach(v -> {
            try {
                v.updatePublicKey();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.error("Interrupted while updating public key for issuer: {}, last success time: {}",
                        v.getIssuer(),
                        v.isReady() ? v.getLastUpdateTime() : "NULL");
            } catch (Exception e) {
                logger.error("Failed to update public key for issuer: {}, last success time: {}, error: {}",
                        v.getIssuer(),
                        v.isReady() ? v.getLastUpdateTime() : "NULL",
                        e.getMessage());
            }
        });
    }

    /**
     * 验证和解析 JWT
     *
     * @param signedToken
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public VerifiedClaims verify(String signedToken) throws GeneralSecurityException, IOException {
        // 直接解析确定签发者
        String[] parts = signedToken.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid JWT format");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String claimedIssuer = objectMapper.readTree(payloadJson).path("iss").asText();
        if (verifyMap.containsKey(claimedIssuer)) {
            return verifyMap.get(claimedIssuer).verify(signedToken).setRawPayload(payloadJson);
        } else {
            throw new GeneralSecurityException("Unknown issuer: " + claimedIssuer);
        }
    }

    /**
     * Expose the public key set as a JSON response through an HTTP endpoint.
     *
     * @param request  the HTTP servlet request
     * @param response the HTTP servlet response
     */
    public void exposePublicKeyThroughEndpoint(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Content-Type", "application/json");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        try {
            response.getWriter().write(publicKeySetAsJSONString);
        } catch (IOException e) {
            logger.error("Error writing public keyset to response", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Get a new JWT signer for the current issuer.
     *
     * @return a JsonWebTokenSigner instance
     */
    public JsonWebTokenSigner getSigner() {
        return new JsonWebTokenSigner(this.jwtPublicKeySign, this.issuer);
    }

    /**
     * Load or generate the private keyset for signing JWTs.
     *
     * @throws GeneralSecurityException if cryptographic operations fail
     * @throws IOException              if file operations fail
     */
    private void handlePrivateKeysetHandle() throws GeneralSecurityException, IOException {
        KeysetHandle privateKeysetHandle;
        Path privateKeysetPath = Paths.get(trustaProperties.getPrivateKeysetFile());
        // 检查私钥文件是否存在
        if (!Files.exists(privateKeysetPath)) {
            // 如果文件不存在，创建 JWT_ES256 密钥对
            privateKeysetHandle = KeysetHandle.generateNew(
                    JwtEcdsaParameters.builder()
                            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                            .build());
            Files.writeString(privateKeysetPath,
                    TinkJsonProtoKeysetFormat.serializeKeyset(privateKeysetHandle,
                            InsecureSecretKeyAccess.get()));
        } else {
            privateKeysetHandle = TinkJsonProtoKeysetFormat.parseKeyset(
                    Files.readString(privateKeysetPath),
                    InsecureSecretKeyAccess.get());
        }
        this.jwtPublicKeySign = privateKeysetHandle.getPrimitive(RegistryConfiguration.get(),
                JwtPublicKeySign.class);
        this.publicKeySetAsJSONString = TinkJsonProtoKeysetFormat.serializeKeyset(
                privateKeysetHandle.getPublicKeysetHandle(),
                InsecureSecretKeyAccess.get());
    }

    /**
     * Register trusted issuers and initialize their verifiers.
     * <p>
     * This method reads the trusted issuers from the configuration, creates a JsonWebTokenVerify
     * instance for each, and stores them in the verifyMap. It then updates the public keys for all issuers.
     */
    private void registerIssuers() {
        String self = trustaProperties.getIssuer();
        boolean allowFetchPublicKeyThroughHTTP = trustaProperties.isAllowHttp();
        List<TrustedIssuer> trustedIssuers = trustaProperties.getTrustedIssuers();
        if (trustedIssuers.isEmpty()) {
            return;
        }
        for (TrustedIssuer trustedIssuer : trustedIssuers) {
            try {
                JsonWebTokenVerify jsonWebTokenVerify = new JsonWebTokenVerify(trustedIssuer, self, allowFetchPublicKeyThroughHTTP);
                verifyMap.put(trustedIssuer.getIssuer(), jsonWebTokenVerify);
            } catch (Exception e) {
                logger.error("Error while creating verify", e);
            }
        }
        updateIssuerPublicKey();
    }
}