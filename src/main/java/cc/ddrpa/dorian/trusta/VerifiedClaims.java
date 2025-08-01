package cc.ddrpa.dorian.trusta;

import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.HashMap;
import java.util.Map;

/**
 * Holds verified claims extracted from a JWT.
 */
@Data
@EqualsAndHashCode(callSuper = false)
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

    /**
     * Set the raw payload string.
     *
     * @param rawPayload the raw JWT payload
     * @return this
     */
    public VerifiedClaims setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
        return this;
    }
}