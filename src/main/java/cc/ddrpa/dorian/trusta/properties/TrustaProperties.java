package cc.ddrpa.dorian.trusta.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

@ConfigurationProperties(prefix = "trusta")
public class TrustaProperties {

    /**
     * 私钥文件位置，用于签发 JWT
     */
    private String privateKeysetFile = "trusta-jwt-es256-private-keyset";
    /**
     * token 签发者（同时作为本系统期望的 audience）
     */
    private String issuer = "";
    /**
     * 允许通过 HTTP 协议获取公钥
     */
    private boolean allowHttp = false;
    /**
     * 受信任签发者
     */
    private List<TrustedIssuer> trustedIssuers = Collections.emptyList();
    /**
     * 签发令牌的默认有效期（秒）；跨系统跳转令牌应保持短生命周期，
     * 上限见 {@link cc.ddrpa.dorian.trusta.JsonWebTokenSigner#MAX_VALIDITY_PERIOD}（600 秒）
     */
    private long tokenValidity = 30;

    public String getPrivateKeysetFile() {
        return privateKeysetFile;
    }

    public void setPrivateKeysetFile(String privateKeysetFile) {
        this.privateKeysetFile = privateKeysetFile;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public boolean isAllowHttp() {
        return allowHttp;
    }

    public void setAllowHttp(boolean allowHttp) {
        this.allowHttp = allowHttp;
    }

    public List<TrustedIssuer> getTrustedIssuers() {
        return trustedIssuers;
    }

    public void setTrustedIssuers(List<TrustedIssuer> trustedIssuers) {
        this.trustedIssuers = trustedIssuers;
    }

    public long getTokenValidity() {
        return tokenValidity;
    }

    public void setTokenValidity(long tokenValidity) {
        this.tokenValidity = tokenValidity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustaProperties that = (TrustaProperties) o;
        return allowHttp == that.allowHttp &&
                tokenValidity == that.tokenValidity &&
                Objects.equals(privateKeysetFile, that.privateKeysetFile) &&
                Objects.equals(issuer, that.issuer) &&
                Objects.equals(trustedIssuers, that.trustedIssuers);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKeysetFile, issuer, allowHttp, trustedIssuers, tokenValidity);
    }

    @Override
    public String toString() {
        return "TrustaProperties{" +
                "privateKeysetFile='" + privateKeysetFile + '\'' +
                ", issuer='" + issuer + '\'' +
                ", allowHttp=" + allowHttp +
                ", trustedIssuers=" + trustedIssuers +
                ", tokenValidity=" + tokenValidity +
                '}';
    }
}
