package cc.ddrpa.dorian.trusta;

import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.RawJwt;
import org.springframework.util.StringUtils;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility for signing JSON Web Tokens (JWT) with custom claims and validity period.
 * Audience and subject must be set explicitly before {@link #sign()}.
 */
public class JsonWebTokenSigner {

    /**
     * Upper bound for a single token's validity period. Trusta tokens are meant to be
     * short-lived cross-system assertions (a single A→B hop); this cap prevents
     * accidentally minting long-lived bearer credentials via configuration or call-site
     * mistakes.
     */
    public static final Duration MAX_VALIDITY_PERIOD = Duration.ofMinutes(10);

    private final JwtPublicKeySign jwtPublicKeySign;
    private final String issuer;
    private final Map<String, String> claims = new HashMap<>();

    private Duration validityPeriod;
    private String subject;
    private String audience;

    /**
     * Create a new JsonWebTokenSigner.
     *
     * @param jwtPublicKeySign the Tink JwtPublicKeySign instance
     * @param issuer           the issuer string
     * @param defaultValidity  default validity for tokens signed through this signer
     */
    protected JsonWebTokenSigner(JwtPublicKeySign jwtPublicKeySign, String issuer, Duration defaultValidity) {
        if (!StringUtils.hasText(issuer)) {
            throw new IllegalStateException("issuer must not be blank");
        }
        this.jwtPublicKeySign = jwtPublicKeySign;
        this.issuer = issuer;
        validateValidityPeriod(defaultValidity);
        this.validityPeriod = defaultValidity;
    }

    /**
     * Set the validity period for the token.
     *
     * @param validityPeriod the duration the token is valid; must be within (0s, {@link #MAX_VALIDITY_PERIOD}]
     * @return this
     */
    public JsonWebTokenSigner setValidityPeriod(Duration validityPeriod) {
        validateValidityPeriod(validityPeriod);
        this.validityPeriod = validityPeriod;
        return this;
    }

    /**
     * Set the subject for the token. Must be the shared identifier agreed with the audience.
     *
     * @param subject the subject
     * @return this
     */
    public JsonWebTokenSigner setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    /**
     * Set the audience for the token. Required; there is no wildcard default.
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
     * @throws IllegalStateException    if subject or audience is missing
     */
    public String sign() throws GeneralSecurityException {
        if (!StringUtils.hasText(subject)) {
            throw new IllegalStateException("Subject must be set before signing the JWT");
        }
        if (!StringUtils.hasText(audience)) {
            throw new IllegalStateException("Audience must be set before signing the JWT; use issueTo(audience)");
        }
        Instant now = Instant.now();
        RawJwt.Builder rawJwtBuilder = RawJwt.newBuilder()
                .setIssuer(issuer)
                .setSubject(subject)
                .setAudience(audience)
                .setIssuedAt(now)
                .setExpiration(now.plus(validityPeriod));
        if (!claims.isEmpty()) {
            claims.forEach(rawJwtBuilder::addStringClaim);
        }
        return jwtPublicKeySign.signAndEncode(rawJwtBuilder.build());
    }

    static void validateValidityPeriod(Duration validityPeriod) {
        if (validityPeriod == null || validityPeriod.isZero() || validityPeriod.isNegative()) {
            throw new IllegalArgumentException("validity period must be positive, got: " + validityPeriod);
        }
        if (validityPeriod.compareTo(MAX_VALIDITY_PERIOD) > 0) {
            throw new IllegalArgumentException("validity period " + validityPeriod
                    + " exceeds the maximum allowed " + MAX_VALIDITY_PERIOD);
        }
    }
}
