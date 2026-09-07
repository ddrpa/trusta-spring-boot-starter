package cc.ddrpa.dorian.trusta;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Holds verified claims extracted from a JWT.
 */
public class VerifiedClaims {
    /**
     * Token issuer ({@code iss}).
     */
    private String issuer;
    /**
     * JWT {@code sub} — the shared identifier used to match a local user.
     */
    private String subject;
    /**
     * All claims of the verified token payload as a string-valued map (unmodifiable).
     * <p>
     * String claims are returned as-is; numbers, booleans, arrays and objects are returned as
     * their compact JSON text; {@code null} claims are kept as {@code null}. {@code iss}/{@code sub}
     * are duplicated here and are also available via {@link #getIssuer()} / {@link #getSubject()}.
     */
    private Map<String, String> claims = Collections.emptyMap();

    public String getIssuer() {
        return issuer;
    }

    public VerifiedClaims setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public VerifiedClaims setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    public Map<String, String> getClaims() {
        return claims;
    }

    public VerifiedClaims setClaims(Map<String, String> claims) {
        this.claims = claims == null || claims.isEmpty()
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifiedClaims that = (VerifiedClaims) o;
        return Objects.equals(issuer, that.issuer) &&
                Objects.equals(subject, that.subject) &&
                Objects.equals(claims, that.claims);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, subject, claims);
    }

    @Override
    public String toString() {
        return "VerifiedClaims{" +
                "issuer='" + issuer + '\'' +
                ", subject='" + subject + '\'' +
                ", claims=" + claims +
                '}';
    }
}
