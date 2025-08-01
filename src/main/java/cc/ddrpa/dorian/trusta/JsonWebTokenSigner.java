package cc.ddrpa.dorian.trusta;

import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.RawJwt;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class JsonWebTokenSigner {
    private static final Duration DEFAULT_VALIDITY_PERIOD = Duration.ofMinutes(3);
    private static final String WILDCARD_AUDIENCE = "*";

    private final JwtPublicKeySign jwtPublicKeySign;
    private final String issuer;
    private final Map<String, String> claims = new HashMap<>();

    private Duration validityPeriod = DEFAULT_VALIDITY_PERIOD;
    private String subject;
    private String audience;

    protected JsonWebTokenSigner(JwtPublicKeySign jwtPublicKeySign, String issuer) {
        this.jwtPublicKeySign = jwtPublicKeySign;
        this.issuer = issuer;
    }

    public JsonWebTokenSigner setValidityPeriod(Duration validityPeriod) {
        this.validityPeriod = validityPeriod;
        return this;
    }

    public JsonWebTokenSigner setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    /**
     * 设置哪个系统接收 token
     *
     * @param audience
     * @return
     */
    public JsonWebTokenSigner setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public JsonWebTokenSigner addClaim(String name, String value) {
        this.claims.put(name, value);
        return this;
    }

    public JsonWebTokenSigner addClaims(Map<String, String> claims) {
        this.claims.putAll(claims);
        return this;
    }

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
