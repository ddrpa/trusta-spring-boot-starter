package cc.ddrpa.dorian.trusta.properties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Collections;
import java.util.Map;

@Data
@Accessors(chain = true)
@NoArgsConstructor
@AllArgsConstructor
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
}