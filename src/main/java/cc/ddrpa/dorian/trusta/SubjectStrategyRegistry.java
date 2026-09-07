package cc.ddrpa.dorian.trusta;

import cc.ddrpa.dorian.trusta.properties.TrustedIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Binds a {@link SubjectStrategy} bean to each trusted issuer, using the {@code identifier}
 * declared in {@code trusta.trusted-issuers}, and resolves strategies by issuer.
 * <p>
 * Issuers sharing the same {@code identifier} class share the same bean instance. Binding is
 * synchronized and idempotent.
 */
class SubjectStrategyRegistry {

    private static final Logger logger = LoggerFactory.getLogger(SubjectStrategyRegistry.class);

    private final ApplicationContext applicationContext;
    private final List<TrustedIssuer> trustedIssuers;

    private final Map<String, SubjectStrategy<?>> strategyMap = new HashMap<>();
    private volatile boolean bound;

    SubjectStrategyRegistry(ApplicationContext applicationContext, List<TrustedIssuer> trustedIssuers) {
        this.applicationContext = applicationContext;
        this.trustedIssuers = trustedIssuers;
    }

    /**
     * Resolves the strategy bound to an issuer, binding lazily on first use if needed.
     *
     * @param issuer the verified issuer
     * @return the bound strategy, or {@code null} when the issuer has no strategy
     */
    SubjectStrategy<?> get(String issuer) {
        ensureBound();
        return strategyMap.get(issuer);
    }

    synchronized void bindAll() {
        if (bound) {
            return;
        }
        Map<Class<?>, SubjectStrategy<?>> beanByClass = new HashMap<>();
        for (TrustedIssuer trustedIssuer : trustedIssuers) {
            Class<? extends SubjectStrategy> identifier = trustedIssuer.getIdentifier();
            if (identifier == null) {
                throw new IllegalStateException(
                        "trusted-issuers[].identifier is required for issuer: " + trustedIssuer.getIssuer());
            }
            if (!SubjectStrategy.class.isAssignableFrom(identifier)) {
                throw new IllegalStateException(
                        "identifier must implement SubjectStrategy for issuer: " + trustedIssuer.getIssuer()
                                + ", got: " + identifier.getName());
            }
            SubjectStrategy<?> strategy = beanByClass.get(identifier);
            if (strategy == null) {
                try {
                    strategy = applicationContext.getBean(identifier);
                } catch (Exception e) {
                    throw new IllegalStateException(
                            "No Spring bean of type " + identifier.getName()
                                    + " for issuer " + trustedIssuer.getIssuer()
                                    + ". Register it with @Component or @Bean.", e);
                }
                beanByClass.put(identifier, strategy);
            }
            strategyMap.put(trustedIssuer.getIssuer(), strategy);
        }
        bound = true;
        logger.info("Bound {} subject strategies for {} trusted issuers",
                beanByClass.size(), strategyMap.size());
    }

    private void ensureBound() {
        if (!bound) {
            bindAll();
        }
    }
}
