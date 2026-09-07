package cc.ddrpa.dorian.trusta.properties;

import cc.ddrpa.dorian.trusta.SubjectStrategy;

import java.util.Objects;

/**
 * A trusted token issuer that this system accepts tokens from.
 */
public class TrustedIssuer {
    /**
     * Token issuer, e.g. {@code system-a.site}.
     */
    private String issuer;
    /**
     * Public key URI; defaults to {@code https://${issuer}/.well-known/trusta-jwks.json}.
     */
    private String publicKeyUri;
    /**
     * {@link SubjectStrategy} implementation class used to match {@code sub} to a local user.
     * Multiple issuers may share the same class.
     */
    private Class<? extends SubjectStrategy> identifier;

    public TrustedIssuer() {
    }

    public TrustedIssuer(String issuer, String publicKeyUri, Class<? extends SubjectStrategy> identifier) {
        this.issuer = issuer;
        this.publicKeyUri = publicKeyUri;
        this.identifier = identifier;
    }

    public String getIssuer() {
        return issuer;
    }

    public TrustedIssuer setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String getPublicKeyUri() {
        return publicKeyUri;
    }

    public TrustedIssuer setPublicKeyUri(String publicKeyUri) {
        this.publicKeyUri = publicKeyUri;
        return this;
    }

    public Class<? extends SubjectStrategy> getIdentifier() {
        return identifier;
    }

    public TrustedIssuer setIdentifier(Class<? extends SubjectStrategy> identifier) {
        this.identifier = identifier;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustedIssuer that = (TrustedIssuer) o;
        return Objects.equals(issuer, that.issuer) &&
                Objects.equals(publicKeyUri, that.publicKeyUri) &&
                Objects.equals(identifier, that.identifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, publicKeyUri, identifier);
    }

    @Override
    public String toString() {
        return "TrustedIssuer{" +
                "issuer='" + issuer + '\'' +
                ", publicKeyUri='" + publicKeyUri + '\'' +
                ", identifier=" + identifier +
                '}';
    }
}
