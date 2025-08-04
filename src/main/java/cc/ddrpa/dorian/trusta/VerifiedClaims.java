package cc.ddrpa.dorian.trusta;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Holds verified claims extracted from a JWT.
 */
public class VerifiedClaims {
    /**
     * The subject of the JWT.
     */
    private String subject;
    /**
     * All claims extracted from the JWT.
     */
    private Map<String, Object> claims = new HashMap<>();
    /**
     * The raw payload of the JWT.
     */
    private String rawPayload;

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public void setClaims(Map<String, Object> claims) {
        this.claims = claims;
    }

    public String getRawPayload() {
        return rawPayload;
    }

    public VerifiedClaims setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
        return this;
    }

    /**
     * Add a claim to the claims map.
     *
     * @param key   claim name
     * @param value claim value
     */
    public void addClaim(String key, Object value) {
        claims.put(key, value);
    }

    /**
     * Get a claim value by name.
     *
     * @param claim claim name
     * @return claim value
     */
    public Object getClaim(String claim) {
        return claims.get(claim);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifiedClaims that = (VerifiedClaims) o;
        return Objects.equals(subject, that.subject) &&
                Objects.equals(claims, that.claims) &&
                Objects.equals(rawPayload, that.rawPayload);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, claims, rawPayload);
    }

    @Override
    public String toString() {
        return "VerifiedClaims{" +
                "subject='" + subject + '\'' +
                ", claims=" + claims +
                ", rawPayload='" + rawPayload + '\'' +
                '}';
    }
}