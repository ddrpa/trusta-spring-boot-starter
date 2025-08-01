package cc.ddrpa.dorian.trusta.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.List;

@Data
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

}