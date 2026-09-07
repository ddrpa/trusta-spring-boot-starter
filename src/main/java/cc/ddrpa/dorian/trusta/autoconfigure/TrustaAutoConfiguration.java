package cc.ddrpa.dorian.trusta.autoconfigure;

import cc.ddrpa.dorian.trusta.TrustaManager;
import cc.ddrpa.dorian.trusta.properties.TrustaProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
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
        JwtSignatureConfig.register();
    }

    @Bean
    @ConditionalOnMissingBean(ObjectMapper.class)
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    @ConditionalOnMissingBean(TrustaManager.class)
    public TrustaManager trustaManager(TrustaProperties trustaProperties,
                                       ObjectMapper objectMapper,
                                       ApplicationContext applicationContext)
            throws GeneralSecurityException, IOException {
        return new TrustaManager(trustaProperties, objectMapper, applicationContext);
    }

    @Bean
    public ApplicationRunner trustaInitializationRunner(
            @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping,
            TrustaManager trustaManager) {
        return args -> {
            trustaManager.bindSubjectStrategies();
            JwksPublicEndpoint endpoint = new JwksPublicEndpoint(trustaManager);
            handlerMapping.registerMapping(
                    RequestMappingInfo
                            .paths(TrustaManager.JWKS_PATH)
                            .methods(RequestMethod.GET)
                            .build(),
                    endpoint,
                    new HandlerMethod(endpoint, "write", HttpServletResponse.class).getMethod());
        };
    }

    /**
     * Handler backing the public JWKS endpoint ({@link TrustaManager#JWKS_PATH}, GET). It is a plain
     * object — not a {@code @Controller} bean — created and registered programmatically by the runner,
     * hence independent of component scanning. Only public key material is written.
     */
    private static final class JwksPublicEndpoint {

        private static final Logger logger = LoggerFactory.getLogger(JwksPublicEndpoint.class);

        private final TrustaManager trustaManager;

        private JwksPublicEndpoint(TrustaManager trustaManager) {
            this.trustaManager = trustaManager;
        }

        public void write(HttpServletResponse response) {
            response.setHeader("Content-Type", "application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);
            try {
                response.getWriter().write(trustaManager.getPublicKeySetAsJSONString());
            } catch (IOException e) {
                logger.error("Error writing public keyset to response", e);
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }
    }
}
