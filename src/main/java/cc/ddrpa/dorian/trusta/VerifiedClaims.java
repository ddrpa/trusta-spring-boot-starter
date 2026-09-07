package cc.ddrpa.dorian.trusta;

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
     * The raw payload of the JWT.
     */
    private String rawPayload;

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

    public String getRawPayload() {
        return rawPayload;
    }

    public VerifiedClaims setRawPayload(String rawPayload) {
        this.rawPayload = rawPayload;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifiedClaims that = (VerifiedClaims) o;
        return Objects.equals(issuer, that.issuer) &&
                Objects.equals(subject, that.subject) &&
                Objects.equals(rawPayload, that.rawPayload);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, subject, rawPayload);
    }

    @Override
    public String toString() {
        return "VerifiedClaims{" +
                "issuer='" + issuer + '\'' +
                ", subject='" + subject + '\'' +
                ", rawPayload='" + rawPayload + '\'' +
                '}';
    }
}
