package cc.ddrpa.dorian.trusta.autoconfigure;

import cc.ddrpa.dorian.trusta.TrustaManager;
import cc.ddrpa.dorian.trusta.properties.TrustaProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Configuration
@EnableConfigurationProperties(TrustaProperties.class)
public class TrustaAutoConfiguration {

    public TrustaAutoConfiguration() throws GeneralSecurityException {
        // Register all JWT signature key types with the Tink runtime.
        JwtSignatureConfig.register();
    }

    @Bean
    @ConditionalOnMissingBean(ObjectMapper.class)
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    public TrustaManager trustaManager(TrustaProperties trustaProperties, ObjectMapper objectMapper) throws GeneralSecurityException, IOException {
        return new TrustaManager(trustaProperties, objectMapper);
    }

    @Bean
    public ApplicationRunner trustaInitializationRunner(
            @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping,
            TrustaManager trustaManager) {
        return args -> handlerMapping.registerMapping(
                RequestMappingInfo
                        .paths("/.well-known/trusta/jwks.json")
                        .methods(RequestMethod.GET)
                        .build(),
                trustaManager,
                new HandlerMethod(trustaManager, "exposePublicKeyThroughEndpoint", HttpServletRequest.class,
                        HttpServletResponse.class).getMethod());
    }
}
