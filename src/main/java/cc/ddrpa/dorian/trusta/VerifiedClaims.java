package cc.ddrpa.dorian.trusta;

import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.HashMap;
import java.util.Map;

@Data
@EqualsAndHashCode(callSuper = false)
public class VerifiedClaims {
    private String subject;
    private Map<String, Object> claims = new HashMap<>();
    private String rawPayload;

    public void addClaim(String key, Object value) {
        claims.put(key, value);
    }

    public Object getClaim(String claim) {
        return claims.get(claim);
    }

    public VerifiedClaims setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
        return this;
    }
}