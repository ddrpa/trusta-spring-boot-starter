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
    private String privateKeysetFile = ".jwt-es256-private-keyset";
    /**
     * token 签发者
     */
    private String issuer = "";
    /**
     * 允许通过 HTTP 协议获取公钥
     */
    private boolean allowHttp = false;
    private List<TrustedIssuer> trustedIssuers = Collections.emptyList();

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustaProperties that = (TrustaProperties) o;
        return allowHttp == that.allowHttp &&
                Objects.equals(privateKeysetFile, that.privateKeysetFile) &&
                Objects.equals(issuer, that.issuer) &&
                Objects.equals(trustedIssuers, that.trustedIssuers);
    }

    @Override
    public int hashCode() {
        return Objects.hash(privateKeysetFile, issuer, allowHttp, trustedIssuers);
    }

    @Override
    public String toString() {
        return "TrustaProperties{" +
                "privateKeysetFile='" + privateKeysetFile + '\'' +
                ", issuer='" + issuer + '\'' +
                ", allowHttp=" + allowHttp +
                ", trustedIssuers=" + trustedIssuers +
                '}';
    }
}