package cc.ddrpa.dorian.trusta;

import cc.ddrpa.dorian.trusta.properties.TrustedIssuer;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.VerifiedJwt;
import lombok.Getter;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Utility for verifying JSON Web Tokens (JWT) and extracting claims.
 */
public class JsonWebTokenVerify {

    private static final List<String> CLAIM_KEYWORDS = List.of("iss", "sub", "aud", "exp", "nbf", "iat", "jti");
    private static final String CLAIM_SUBJECT = "sub";

    @Getter
    private final String issuer;
    private final URI publicKeyURI;
    private final boolean requireCustomSubject;
    private final String subjectClaimName;
    private final boolean requireAdditionalClaims;
    private final Map<String, String> claimMapping;
    private final JwtValidator jwtValidator;

    @Getter
    private LocalDateTime lastUpdateTime = LocalDateTime.now();
    @Getter
    private boolean ready = false;

    private JwtPublicKeyVerify jwtPublicKeyVerify;

    /**
     * Construct a new JsonWebTokenVerify instance.
     *
     * @param issuer                         TrustedIssuer configuration
     * @param self                           self identifier
     * @param allowFetchPublicKeyThroughHTTP allow HTTP fetch for public key
     */
    public JsonWebTokenVerify(TrustedIssuer issuer, String self, boolean allowFetchPublicKeyThroughHTTP) {
        String issuerName = issuer.getIssuer();
        this.issuer = issuerName;
        if (StringUtils.hasText(issuer.getPublicKeyUri())) {
            URI uri = URI.create(issuer.getPublicKeyUri());
            if (!allowFetchPublicKeyThroughHTTP && uri.getScheme().equals("http")) {
                throw new IllegalArgumentException("HTTP URI scheme is not allowed");
            } else {
                this.publicKeyURI = uri;
            }
        } else {
            this.publicKeyURI = URI.create("https://" + issuerName + "/.well-known/trusta/jwks.json");
        }
        String audience;
        if (StringUtils.hasText(issuer.getCustomAudience())) {
            audience = issuer.getCustomAudience();
        } else {
            audience = self;
        }
        boolean expectAudience = issuer.isExpectAudience();
        JwtValidator.Builder builder = JwtValidator.newBuilder()
                .expectIssuer(issuerName);
        if (expectAudience) {
            builder.expectAudience(audience);
        } else {
            builder.ignoreAudiences();
        }
        this.jwtValidator = builder.build();
        // subject 映射
        if (StringUtils.hasText(issuer.getSubject())) {
            if (CLAIM_SUBJECT.equals(issuer.getSubject())) {
                this.requireCustomSubject = false;
                this.subjectClaimName = "sub";
            } else if (CLAIM_KEYWORDS.contains(issuer.getSubject())) {
                throw new IllegalArgumentException("Using keyword is not allowed");
            } else {
                this.requireCustomSubject = true;
                this.subjectClaimName = issuer.getSubject();
            }
        } else {
            // 默认使用 sub 字段
            this.requireCustomSubject = false;
            this.subjectClaimName = "sub";
        }
        // 其他 claim 映射
        this.claimMapping = issuer.getClaimMapping();
        this.requireAdditionalClaims = !this.claimMapping.isEmpty();
    }

    /**
     * 验证并解析给定的 JWT
     *
     * @param signedToken
     * @return
     * @throws GeneralSecurityException
     */
    public VerifiedClaims verify(final String signedToken) throws GeneralSecurityException {
        if (!this.ready) {
            throw new IllegalStateException("Public key is not ready, please try updatePublicKey() again");
        }

        VerifiedJwt verifiedJwt = jwtPublicKeyVerify.verifyAndDecode(signedToken, this.jwtValidator);
        VerifiedClaims verifiedClaims = new VerifiedClaims();
        if (this.requireCustomSubject) {
            verifiedClaims.setSubject(verifiedJwt.getStringClaim(this.subjectClaimName));
        } else {
            verifiedClaims.setSubject(verifiedJwt.getSubject());
        }
        if (this.requireAdditionalClaims) {
            for (Map.Entry<String, String> entry : this.claimMapping.entrySet()) {
                String entryKey = entry.getKey();
                String mappedKey = entry.getValue();
                switch (entryKey) {
                    case "iss" -> verifiedClaims.addClaim(mappedKey, verifiedJwt.getIssuer());
                    case "sub" -> verifiedClaims.addClaim(mappedKey, verifiedJwt.getSubject());
                    case "aud" -> verifiedClaims.addClaim(mappedKey, verifiedJwt.getAudiences());
                    case "exp" -> verifiedClaims.addClaim(mappedKey, verifiedJwt.getExpiration());
                    case "nbf" -> verifiedClaims.addClaim(mappedKey, verifiedJwt.getNotBefore());
                    case "iat" -> verifiedClaims.addClaim(mappedKey, verifiedJwt.getIssuedAt());
                    case "jti" -> verifiedClaims.addClaim(mappedKey, verifiedJwt.getJwtId());
                    default -> {
                        String claimValue = verifiedJwt.getStringClaim(entryKey);
                        if (Objects.nonNull(claimValue)) {
                            verifiedClaims.addClaim(mappedKey, claimValue);
                        }
                    }
                }
            }
        }
        return verifiedClaims;
    }

    /**
     * 更新对端公钥集
     *
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws InterruptedException
     */
    public void updatePublicKey() throws GeneralSecurityException, IOException, InterruptedException {
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(publicKeyURI)
                .timeout(Duration.ofSeconds(10))
                .build();
        HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to fetch public keyset from " + publicKeyURI
                    + ", status code: " + response.statusCode());
        }
        String publicKeysetAsString = response.body();
        // 将 JWK Set 转换为 PublicKeysetHandle
        KeysetHandle publicKeysetHandle = TinkJsonProtoKeysetFormat.parseKeyset(publicKeysetAsString, InsecureSecretKeyAccess.get());

        this.jwtPublicKeyVerify = publicKeysetHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
        this.lastUpdateTime = LocalDateTime.now();
        this.ready = true;
    }
}
