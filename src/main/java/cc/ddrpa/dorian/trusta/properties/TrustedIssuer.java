package cc.ddrpa.dorian.trusta.properties;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

public class TrustedIssuer {
    // token 签发者，example: system-a.site/context/path
    private String issuer;
    // 公钥地址，默认为 https://${issuer}/.well-known/trusta/jwks.json
    private String publicKeyUri;
    // 是否验证 audience 字段
    private boolean expectAudience;
    // 若需要验证 audience 字段，则使用 issuer，但有该字段时覆盖
    private String customAudience;
    // subject 字段映射，不支持 JWT 关键字，未配置或配置错误时回落到使用 sub 字段
    private String subject;
    private Map<String, String> claimMapping = Collections.emptyMap();

    public TrustedIssuer() {
    }

    public TrustedIssuer(String issuer, String publicKeyUri, boolean expectAudience, String customAudience, String subject, Map<String, String> claimMapping) {
        this.issuer = issuer;
        this.publicKeyUri = publicKeyUri;
        this.expectAudience = expectAudience;
        this.customAudience = customAudience;
        this.subject = subject;
        this.claimMapping = claimMapping;
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

    public boolean isExpectAudience() {
        return expectAudience;
    }

    public TrustedIssuer setExpectAudience(boolean expectAudience) {
        this.expectAudience = expectAudience;
        return this;
    }

    public String getCustomAudience() {
        return customAudience;
    }

    public TrustedIssuer setCustomAudience(String customAudience) {
        this.customAudience = customAudience;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public TrustedIssuer setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    public Map<String, String> getClaimMapping() {
        return claimMapping;
    }

    public TrustedIssuer setClaimMapping(Map<String, String> claimMapping) {
        this.claimMapping = claimMapping;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustedIssuer that = (TrustedIssuer) o;
        return expectAudience == that.expectAudience &&
                Objects.equals(issuer, that.issuer) &&
                Objects.equals(publicKeyUri, that.publicKeyUri) &&
                Objects.equals(customAudience, that.customAudience) &&
                Objects.equals(subject, that.subject) &&
                Objects.equals(claimMapping, that.claimMapping);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, publicKeyUri, expectAudience, customAudience, subject, claimMapping);
    }

    @Override
    public String toString() {
        return "TrustedIssuer{" +
                "issuer='" + issuer + '\'' +
                ", publicKeyUri='" + publicKeyUri + '\'' +
                ", expectAudience=" + expectAudience +
                ", customAudience='" + customAudience + '\'' +
                ", subject='" + subject + '\'' +
                ", claimMapping=" + claimMapping +
                '}';
    }
}