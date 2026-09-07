package cc.ddrpa.dorian.trusta;

import cc.ddrpa.dorian.trusta.properties.TrustaProperties;
import cc.ddrpa.dorian.trusta.properties.TrustedIssuer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyStatus;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.util.StringUtils;

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
import java.util.Optional;

/**
 * Central manager for Trusta JWT operations: signing, verification, key rotation,
 * and subject resolution via {@link SubjectStrategy}.
 */
public class TrustaManager {

    public static final String JWKS_PATH = "/.well-known/trusta-jwks.json";

    private static final Logger logger = LoggerFactory.getLogger(TrustaManager.class);

    private final TrustaProperties trustaProperties;
    private final ObjectMapper objectMapper;
    private final ApplicationContext applicationContext;
    private final String issuer;
    private final Path privateKeysetPath;

    private final Map<String, JsonWebTokenVerify> verifyMap = new HashMap<>();
    private final Map<String, SubjectStrategy<?>> strategyMap = new HashMap<>();

    private volatile KeysetHandle privateKeysetHandle;
    private volatile String publicKeySetAsJSONString;
    private volatile JwtPublicKeySign jwtPublicKeySign;
    private volatile boolean strategiesBound;

    public TrustaManager(TrustaProperties trustaProperties, ObjectMapper objectMapper,
                         ApplicationContext applicationContext) throws GeneralSecurityException, IOException {
        this.trustaProperties = trustaProperties;
        this.objectMapper = objectMapper;
        this.applicationContext = applicationContext;
        this.issuer = trustaProperties.getIssuer();
        this.privateKeysetPath = Paths.get(trustaProperties.getPrivateKeysetFile());

        handlePrivateKeysetHandle();
        registerIssuers();
    }

    /**
     * Create a signer targeted at a specific audience. Audience is required.
     */
    public JsonWebTokenSigner issueTo(String audience) {
        if (!StringUtils.hasText(audience)) {
            throw new IllegalArgumentException("audience must not be blank");
        }
        return new JsonWebTokenSigner(this.jwtPublicKeySign, this.issuer).setAudience(audience);
    }

    /**
     * Get a new JWT signer for the current issuer. Audience must still be set before {@code sign()}.
     */
    public JsonWebTokenSigner getSigner() {
        return new JsonWebTokenSigner(this.jwtPublicKeySign, this.issuer);
    }

    /**
     * Manually refresh cached public keys for all trusted issuers.
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
     * Verify and parse a JWT from a trusted issuer.
     */
    public VerifiedClaims verify(String signedToken) throws GeneralSecurityException, IOException {
        String[] parts = signedToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String claimedIssuer = objectMapper.readTree(payloadJson).path("iss").asText();
        JsonWebTokenVerify verifier = verifyMap.get(claimedIssuer);
        if (verifier == null) {
            throw new GeneralSecurityException("Unknown issuer: " + claimedIssuer);
        }
        return verifier.verify(signedToken).setRawPayload(payloadJson);
    }

    /**
     * Verify a token and resolve it to a local user through the issuer's {@link SubjectStrategy}.
     */
    @SuppressWarnings("unchecked")
    public <T> T resolve(String signedToken) throws GeneralSecurityException, IOException {
        ensureStrategiesBound();
        VerifiedClaims claims = verify(signedToken);
        SubjectStrategy<T> strategy = (SubjectStrategy<T>) strategyMap.get(claims.getIssuer());
        if (strategy == null) {
            throw new IllegalStateException("No SubjectStrategy bound for issuer: " + claims.getIssuer());
        }
        Optional<T> found = strategy.find(claims.getSubject(), claims);
        return found.orElseGet(() -> strategy.register(claims.getSubject(), claims));
    }

    /**
     * Bind {@link SubjectStrategy} beans declared by {@code trusted-issuers[].identifier}.
     * Must run after the application context has finished creating user beans.
     */
    public synchronized void bindSubjectStrategies() {
        if (strategiesBound) {
            return;
        }
        Map<Class<?>, SubjectStrategy<?>> beanByClass = new HashMap<>();
        for (TrustedIssuer trustedIssuer : trustaProperties.getTrustedIssuers()) {
            Class<? extends SubjectStrategy> identifier = trustedIssuer.getIdentifier();
            if (identifier == null) {
                throw new IllegalStateException(
                        "trusted-issuers[].identifier is required for issuer: " + trustedIssuer.getIssuer());
            }
            if (!SubjectStrategy.class.isAssignableFrom(identifier)) {
                throw new IllegalStateException(
                        "identifier must implement SubjectStrategy for issuer: " + trustedIssuer.getIssuer()
                                + ", got: " + identifier.getName());
            }
            SubjectStrategy<?> strategy = beanByClass.get(identifier);
            if (strategy == null) {
                try {
                    strategy = applicationContext.getBean(identifier);
                } catch (Exception e) {
                    throw new IllegalStateException(
                            "No Spring bean of type " + identifier.getName()
                                    + " for issuer " + trustedIssuer.getIssuer()
                                    + ". Register it with @Component or @Bean.", e);
                }
                beanByClass.put(identifier, strategy);
            }
            strategyMap.put(trustedIssuer.getIssuer(), strategy);
        }
        strategiesBound = true;
        logger.info("Bound {} subject strategies for {} trusted issuers",
                beanByClass.size(), strategyMap.size());
    }

    /**
     * Rotate the signing key: add a new ES256 primary key with kid, persist, refresh JWKS.
     *
     * @return the new primary key id
     */
    public synchronized int rotateSigningKey() throws GeneralSecurityException, IOException {
        JwtEcdsaParameters parameters = jwtEcdsaParameters();
        KeysetHandle.Builder builder = KeysetHandle.newBuilder(privateKeysetHandle);
        builder.addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary());
        applyKeyset(builder.build());
        int primaryId = privateKeysetHandle.getPrimary().getId();
        logger.info("Rotated signing key, new primary key id={}", primaryId);
        return primaryId;
    }

    /**
     * Disable a non-primary signing key by Tink key id.
     */
    public synchronized void disableSigningKey(int keyId) throws GeneralSecurityException, IOException {
        if (privateKeysetHandle.getPrimary().getId() == keyId) {
            throw new IllegalArgumentException("Cannot disable the primary signing key id=" + keyId);
        }
        KeysetHandle.Builder fresh = KeysetHandle.newBuilder();
        boolean found = false;
        for (int i = 0; i < privateKeysetHandle.size(); i++) {
            KeysetHandle.Entry entry = privateKeysetHandle.getAt(i);
            KeysetHandle.Builder.Entry imported = KeysetHandle.importKey(entry.getKey()).withFixedId(entry.getId());
            if (entry.getId() == keyId) {
                imported.setStatus(KeyStatus.DISABLED);
                found = true;
            } else {
                imported.setStatus(entry.getStatus());
            }
            if (entry.isPrimary()) {
                imported.makePrimary();
            }
            fresh.addEntry(imported);
        }
        if (!found) {
            throw new IllegalArgumentException("Unknown signing key id=" + keyId);
        }
        applyKeyset(fresh.build());
        logger.info("Disabled signing key id={}", keyId);
    }

    /**
     * Disable all non-primary keys after a rotation grace period.
     */
    public synchronized void disableNonPrimaryKeys() throws GeneralSecurityException, IOException {
        int primaryId = privateKeysetHandle.getPrimary().getId();
        KeysetHandle.Builder fresh = KeysetHandle.newBuilder();
        int disabled = 0;
        for (int i = 0; i < privateKeysetHandle.size(); i++) {
            KeysetHandle.Entry entry = privateKeysetHandle.getAt(i);
            KeysetHandle.Builder.Entry imported = KeysetHandle.importKey(entry.getKey()).withFixedId(entry.getId());
            if (entry.getId() == primaryId) {
                imported.setStatus(KeyStatus.ENABLED).makePrimary();
            } else if (entry.getStatus() == KeyStatus.ENABLED) {
                imported.setStatus(KeyStatus.DISABLED);
                disabled++;
            } else {
                imported.setStatus(entry.getStatus());
            }
            fresh.addEntry(imported);
        }
        applyKeyset(fresh.build());
        logger.info("Disabled {} non-primary signing keys; primary id={}", disabled, primaryId);
    }

    /**
     * Expose the public key set as a JSON response through an HTTP endpoint.
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

    public String getPublicKeySetAsJSONString() {
        return publicKeySetAsJSONString;
    }

    public int getPrimaryKeyId() {
        return privateKeysetHandle.getPrimary().getId();
    }

    private void ensureStrategiesBound() {
        if (!strategiesBound) {
            bindSubjectStrategies();
        }
    }

    private void applyKeyset(KeysetHandle handle) throws GeneralSecurityException, IOException {
        this.privateKeysetHandle = handle;
        this.jwtPublicKeySign = privateKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
        this.publicKeySetAsJSONString = TinkJsonProtoKeysetFormat.serializeKeyset(
                privateKeysetHandle.getPublicKeysetHandle(),
                InsecureSecretKeyAccess.get());
        Files.writeString(privateKeysetPath,
                TinkJsonProtoKeysetFormat.serializeKeyset(privateKeysetHandle, InsecureSecretKeyAccess.get()));
    }

    private void handlePrivateKeysetHandle() throws GeneralSecurityException, IOException {
        KeysetHandle handle;
        if (!Files.exists(privateKeysetPath)) {
            handle = KeysetHandle.generateNew(jwtEcdsaParameters());
            Files.writeString(privateKeysetPath,
                    TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()));
        } else {
            handle = TinkJsonProtoKeysetFormat.parseKeyset(
                    Files.readString(privateKeysetPath),
                    InsecureSecretKeyAccess.get());
        }
        this.privateKeysetHandle = handle;
        this.jwtPublicKeySign = privateKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
        this.publicKeySetAsJSONString = TinkJsonProtoKeysetFormat.serializeKeyset(
                privateKeysetHandle.getPublicKeysetHandle(),
                InsecureSecretKeyAccess.get());
    }

    private static JwtEcdsaParameters jwtEcdsaParameters() throws GeneralSecurityException {
        return JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build();
    }

    private void registerIssuers() {
        String self = trustaProperties.getIssuer();
        boolean allowFetchPublicKeyThroughHTTP = trustaProperties.isAllowHttp();
        List<TrustedIssuer> trustedIssuers = trustaProperties.getTrustedIssuers();
        if (trustedIssuers.isEmpty()) {
            return;
        }
        for (TrustedIssuer trustedIssuer : trustedIssuers) {
            if (!StringUtils.hasText(trustedIssuer.getIssuer())) {
                throw new IllegalStateException("trusted-issuers[].issuer must not be blank");
            }
            if (trustedIssuer.getIdentifier() == null) {
                throw new IllegalStateException(
                        "trusted-issuers[].identifier is required for issuer: " + trustedIssuer.getIssuer());
            }
            JsonWebTokenVerify jsonWebTokenVerify = new JsonWebTokenVerify(
                    trustedIssuer, self, allowFetchPublicKeyThroughHTTP, objectMapper);
            verifyMap.put(trustedIssuer.getIssuer(), jsonWebTokenVerify);
        }
        // Do not prefetch public keys at startup; fetch on demand by kid / first verify.
    }
}
