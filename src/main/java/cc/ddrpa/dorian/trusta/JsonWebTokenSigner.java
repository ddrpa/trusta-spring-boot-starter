package cc.ddrpa.dorian.trusta;

import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.RawJwt;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Utility for signing JSON Web Tokens (JWT) with custom claims and validity period.
 */
public class JsonWebTokenSigner {
    private static final Duration DEFAULT_VALIDITY_PERIOD = Duration.ofMinutes(3);
    private static final String WILDCARD_AUDIENCE = "*";

    private final JwtPublicKeySign jwtPublicKeySign;
    private final String issuer;
    private final Map<String, String> claims = new HashMap<>();

    private Duration validityPeriod = DEFAULT_VALIDITY_PERIOD;
    private String subject;
    private String audience;

    /**
     * Create a new JsonWebTokenSigner.
     *
     * @param jwtPublicKeySign the Tink JwtPublicKeySign instance
     * @param issuer           the issuer string
     */
    protected JsonWebTokenSigner(JwtPublicKeySign jwtPublicKeySign, String issuer) {
        this.jwtPublicKeySign = jwtPublicKeySign;
        this.issuer = issuer;
    }

    /**
     * Set the validity period for the token.
     *
     * @param validityPeriod the duration the token is valid
     * @return this
     */
    public JsonWebTokenSigner setValidityPeriod(Duration validityPeriod) {
        this.validityPeriod = validityPeriod;
        return this;
    }

    /**
     * Set the subject for the token.
     *
     * @param subject the subject
     * @return this
     */
    public JsonWebTokenSigner setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    /**
     * Set the audience for the token.
     *
     * @param audience the audience
     * @return this
     */
    public JsonWebTokenSigner setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Add a custom claim to the token.
     *
     * @param name  claim name
     * @param value claim value
     * @return this
     */
    public JsonWebTokenSigner addClaim(String name, String value) {
        this.claims.put(name, value);
        return this;
    }

    /**
     * Add multiple custom claims to the token.
     *
     * @param claims map of claims
     * @return this
     */
    public JsonWebTokenSigner addClaims(Map<String, String> claims) {
        this.claims.putAll(claims);
        return this;
    }

    /**
     * Sign and encode the JWT with the configured claims and validity.
     *
     * @return the signed JWT as a string
     * @throws GeneralSecurityException if signing fails
     */
    public String sign() throws GeneralSecurityException {
        if (Objects.isNull(subject)) {
            throw new IllegalStateException("Subject must be set before signing the JWT");
        }
        Instant now = Instant.now();
        RawJwt.Builder rawJwtBuilder = RawJwt.newBuilder()
                .setIssuer(issuer)
                .setSubject(subject)
                .setIssuedAt(Instant.now())
                .setExpiration(now.plus(validityPeriod));
        if (Objects.nonNull(audience)) {
            rawJwtBuilder.setAudience(audience);
        } else {
            rawJwtBuilder.setAudience(WILDCARD_AUDIENCE);
        }
        if (!claims.isEmpty()) {
            claims.forEach(rawJwtBuilder::addStringClaim);
        }
        return jwtPublicKeySign.signAndEncode(rawJwtBuilder.build());
    }
}
