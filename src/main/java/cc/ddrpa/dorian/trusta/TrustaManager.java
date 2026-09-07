package cc.ddrpa.dorian.trusta;

import cc.ddrpa.dorian.trusta.exceptions.SilentRegisterUnsupportedException;
import cc.ddrpa.dorian.trusta.properties.TrustaProperties;
import cc.ddrpa.dorian.trusta.properties.TrustedIssuer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Facade for the Trusta flow: issuing short-lived JWTs to explicit audiences, verifying tokens from
 * trusted issuers, and resolving their subjects to local users through per-issuer
 * {@link SubjectStrategy SubjectStrategies}.
 * <p>
 * The manager coordinates four collaborators — {@link JsonWebTokenVerify} (per-issuer verification
 * and public-key caching), {@link KeysetStore} (local signing keyset lifecycle), the issuer→strategy
 * binding and the verification registry. Public methods of the manager are thread-safe: verification
 * is lock-free over volatile verifier state; key mutations are synchronized inside {@link KeysetStore};
 * strategy binding is synchronized inside its registry. The public JWKS endpoint is registered by the
 * auto-configuration (programmatic mapping), not by this class.
 */
public class TrustaManager {

    /** Well-known path (GET) at which this system publishes its public keyset. */
    public static final String JWKS_PATH = "/.well-known/trusta-jwks.json";

    private static final Logger logger = LoggerFactory.getLogger(TrustaManager.class);

    private final TrustaProperties trustaProperties;
    private final String issuer;
    private final Duration defaultTokenValidity;
    private final ObjectMapper objectMapper;
    private final KeysetStore keysetStore;
    private final SubjectStrategyRegistry subjectStrategyRegistry;
    private final Map<String, JsonWebTokenVerify> verifyMap = new HashMap<>();

    /**
     * Creates the manager: loads or provisions the local signing keyset, then registers the
     * configured trusted issuers (public keys are not fetched until first verification).
     * <p>
     * Configuration is validated fail-fast:
     * <ul>
     *   <li>{@code trusta.issuer} must be non-blank;</li>
     *   <li>{@code trusta.private-keyset-file} must be non-blank; a missing keyset file is generated
     *       automatically on startup with owner-only permissions;</li>
     *   <li>{@code trusta.token-validity} must be within (0, {@link JsonWebTokenSigner#MAX_VALIDITY_PERIOD}].</li>
     * </ul>
     *
     * @param trustaProperties    the Trusta configuration
     * @param objectMapper        JSON mapper used for issuer routing and claim extraction
     * @param applicationContext  Spring context used to resolve {@link SubjectStrategy} beans
     * @throws IllegalArgumentException if {@code token-validity} is out of range
     * @throws IllegalStateException    if the issuer is blank, the keyset file is missing without
     *                                  auto-generation, or its permissions are too open
     * @throws GeneralSecurityException if the signing keyset cannot be generated or parsed
     * @throws IOException              if the keyset file cannot be read or written
     */
    public TrustaManager(TrustaProperties trustaProperties, ObjectMapper objectMapper,
                         ApplicationContext applicationContext) throws GeneralSecurityException, IOException {
        this.trustaProperties = trustaProperties;
        this.issuer = trustaProperties.getIssuer();
        if (!StringUtils.hasText(this.issuer)) {
            throw new IllegalStateException(
                    "trusta.issuer must be set; it identifies this system as a token issuer and "
                            + "is the audience expected when verifying inbound tokens");
        }
        String privateKeysetFile = trustaProperties.getPrivateKeysetFile();
        if (!StringUtils.hasText(privateKeysetFile)) {
            throw new IllegalStateException("trusta.private-keyset-file must not be blank");
        }
        long tokenValiditySeconds = trustaProperties.getTokenValidity();
        if (tokenValiditySeconds <= 0
                || tokenValiditySeconds > JsonWebTokenSigner.MAX_VALIDITY_PERIOD.toSeconds()) {
            throw new IllegalArgumentException("trusta.token-validity must be within (0, "
                    + JsonWebTokenSigner.MAX_VALIDITY_PERIOD.toSeconds() + "] seconds, got: "
                    + tokenValiditySeconds);
        }
        this.defaultTokenValidity = Duration.ofSeconds(tokenValiditySeconds);
        this.objectMapper = objectMapper;
        this.keysetStore = new KeysetStore(Paths.get(privateKeysetFile));
        this.subjectStrategyRegistry = new SubjectStrategyRegistry(
                applicationContext, trustaProperties.getTrustedIssuers());
        registerIssuers();
    }

    /**
     * Creates a signer pre-bound to the given audience. This is the recommended entry point for
     * issuing: the {@code aud} claim is mandatory (no wildcard) and will be verified by receivers
     * against their own {@code trusta.issuer}.
     * <p>
     * The returned signer still requires a subject ({@code setSubject(...)}) and may set a custom
     * validity period before {@link JsonWebTokenSigner#sign()}.
     *
     * @param audience the token audience ({@code aud} claim); must not be blank
     * @return a signer builder targeting {@code audience}, with the configured default validity
     * @throws IllegalArgumentException if {@code audience} is blank
     */
    public JsonWebTokenSigner issueTo(String audience) {
        if (!StringUtils.hasText(audience)) {
            throw new IllegalArgumentException("audience must not be blank");
        }
        return new JsonWebTokenSigner(this.keysetStore.getSignPrimitive(), this.issuer,
                this.defaultTokenValidity).setAudience(audience);
    }

    /**
     * Creates an unbound signer for this system's issuer. The audience must still be set explicitly
     * before signing — prefer {@link #issueTo(String)} to avoid forgetting it.
     *
     * @return a signer builder with no audience set, using the configured default validity
     */
    public JsonWebTokenSigner getSigner() {
        return new JsonWebTokenSigner(this.keysetStore.getSignPrimitive(), this.issuer,
                this.defaultTokenValidity);
    }

    /**
     * Manually refreshes the cached public keys for every trusted issuer (e.g. from a scheduler after
     * key rotation). Per-issuer failures are logged and do not abort the remaining issuers; issuers
     * that were already ready keep their previous keyset when a refresh fails.
     * <p>
     * Manual refreshes bypass the on-demand refresh backoff used during verification.
     */
    public void updateIssuerPublicKey() {
        logger.info("Updating issuer public keys");
        verifyMap.values().forEach(v -> {
            try {
                v.updatePublicKey();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.error("Interrupted while updating public key for issuer: {}, last success time: {}",
                        v.getIssuer(),
                        v.isReady() ? v.getLastUpdateTime() : "NULL");
            } catch (Exception e) {
                logger.error("Failed to update public key for issuer: {}, last success time: {}, error: {}",
                        v.getIssuer(),
                        v.isReady() ? v.getLastUpdateTime() : "NULL",
                        e.getMessage());
            }
        });
    }

    /**
     * Verifies a signed JWT from a configured trusted issuer: signature, {@code iss} and {@code aud}
     * (this system's own issuer), and expiration are validated cryptographically via Tink. The issuer
     * is routed by the (untrusted) {@code iss} claim, then re-checked against the issuer's keyset.
     * <p>
     * Public keys are cached and fetched on demand (see {@link JsonWebTokenVerify}); the returned
     * {@link VerifiedClaims} exposes {@code iss}, {@code sub} and the full payload as an unmodifiable
     * string-valued {@code claims} map.
     *
     * @param signedToken the JWT to verify
     * @return verified claims (issuer, subject, and all payload claims as strings)
     * @throws IllegalArgumentException  if the token exceeds {@link JsonWebTokenVerify#MAX_TOKEN_LENGTH}
     *                                   characters or is not a well-formed three-part JWT
     * @throws GeneralSecurityException if the issuer is not trusted, the signature is invalid, the
     *                                   token is expired, or the public keyset cannot be fetched
     * @throws IOException              if the JWT payload cannot be decoded as JSON
     */
    public VerifiedClaims verify(String signedToken) throws GeneralSecurityException, IOException {
        if (signedToken.length() > JsonWebTokenVerify.MAX_TOKEN_LENGTH) {
            throw new IllegalArgumentException("JWT exceeds the maximum supported length of "
                    + JsonWebTokenVerify.MAX_TOKEN_LENGTH + " characters");
        }
        String[] parts = signedToken.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        JsonNode payloadNode = objectMapper.readTree(payloadJson);
        String claimedIssuer = payloadNode.path("iss").asText();
        JsonWebTokenVerify verifier = verifyMap.get(claimedIssuer);
        if (verifier == null) {
            throw new GeneralSecurityException("Unknown issuer: " + claimedIssuer);
        }
        return verifier.verify(signedToken)
                .setClaims(JsonWebTokenVerify.toStringClaimsMap(payloadNode));
    }

    /**
     * Verifies a token (see {@link #verify(String)}) and resolves its subject to a local user
     * through the {@link SubjectStrategy} bound to the token's issuer: {@link SubjectStrategy#find}
     * first, and — if no user is found — {@link SubjectStrategy#register} (silent registration).
     * <p>
     * Strategies are bound lazily on first call if they have not been bound yet (see
     * {@link #bindSubjectStrategies()}). Call this only at entry points that should accept a
     * Trusta token (e.g. a login handoff endpoint), not as a per-request credential check.
     *
     * @param signedToken the JWT to verify and resolve
     * @param <T>         the local user type produced by the {@link SubjectStrategy}
     * @return the local user found or silently registered for the token's subject
     * @throws IllegalArgumentException   if the token is malformed or exceeds the length limit
     * @throws GeneralSecurityException   if the token fails cryptographic verification
     * @throws IOException                if the token payload cannot be decoded
     * @throws IllegalStateException      if no strategy is bound for the token's issuer
     * @throws SilentRegisterUnsupportedException if no user exists and the strategy does not
     *                                    implement {@link SubjectStrategy#register}
     */
    @SuppressWarnings("unchecked")
    public <T> T resolve(String signedToken) throws GeneralSecurityException, IOException {
        VerifiedClaims claims = verify(signedToken);
        SubjectStrategy<T> strategy = (SubjectStrategy<T>) subjectStrategyRegistry.get(claims.getIssuer());
        if (strategy == null) {
            throw new IllegalStateException("No SubjectStrategy bound for issuer: " + claims.getIssuer());
        }
        Optional<T> found = strategy.find(claims.getSubject(), claims);
        return found.orElseGet(() -> strategy.register(claims.getSubject(), claims));
    }

    /**
     * Binds a {@link SubjectStrategy} bean to each trusted issuer, using the {@code identifier}
     * declared in {@code trusta.trusted-issuers}. Issuers sharing the same {@code identifier}
     * class share the same bean instance.
     * <p>
     * Called automatically by the auto-configuration after the application context is ready, and
     * lazily by {@link #resolve(String)} if needed. Idempotent; safe to call more than once.
     *
     * @throws IllegalStateException if a trusted issuer is missing its {@code identifier}, the
     *                               class does not implement {@link SubjectStrategy}, or no such
     *                               Spring bean exists
     */
    public synchronized void bindSubjectStrategies() {
        subjectStrategyRegistry.bindAll();
    }

    /**
     * Adds a new ES256 primary key with a fresh {@code kid}, persists the updated keyset atomically
     * and refreshes the published public keyset. Other enabled keys stay enabled, so receivers can
     * still verify tokens signed before the rotation until those keys are disabled (see
     * {@link #disableNonPrimaryKeys()} after a grace period ≥ token validity).
     *
     * @return the Tink key id of the new primary signing key
     * @throws GeneralSecurityException if key generation fails
     * @throws IOException              if the updated keyset cannot be persisted (e.g. read-only mount);
     *                                  on failure the running keyset is left unchanged
     */
    public int rotateSigningKey() throws GeneralSecurityException, IOException {
        return keysetStore.rotateSigningKey();
    }

    /**
     * Disables a non-primary signing key by its Tink key id and persists the change. Tokens signed
     * with the disabled key stop verifying on receivers once they refresh their cached keyset
     * (within the receiver cache TTL).
     *
     * @param keyId the Tink key id of the key to disable (see {@link #getPrimaryKeyId()} for the
     *              current primary; other ids can be listed via the persisted keyset)
     * @throws IllegalArgumentException  if {@code keyId} is the primary key or unknown
     * @throws GeneralSecurityException if rebuilding the keyset fails
     * @throws IOException              if the updated keyset cannot be persisted; on failure the
     *                                  running keyset is left unchanged
     */
    public void disableSigningKey(int keyId) throws GeneralSecurityException, IOException {
        keysetStore.disableSigningKey(keyId);
    }

    /**
     * Disables every enabled non-primary signing key, leaving only the current primary enabled.
     * Intended for the cleanup step after a rotation grace period (≥ token validity): the disabled
     * keys leave the published keyset, and receivers reject tokens signed with them after their next
     * refresh.
     *
     * @throws GeneralSecurityException if rebuilding the keyset fails
     * @throws IOException              if the updated keyset cannot be persisted; on failure the
     *                                  running keyset is left unchanged
     */
    public void disableNonPrimaryKeys() throws GeneralSecurityException, IOException {
        keysetStore.disableNonPrimaryKeys();
    }

    /**
     * Returns the JSON of this system's public keyset, as published on {@link #JWKS_PATH} and used
     * by other systems to verify tokens issued here. Contains public key material only.
     *
     * @return the serialized public keyset JSON
     */
    public String getPublicKeySetAsJSONString() {
        return keysetStore.getPublicKeysetJson();
    }

    /**
     * Returns the Tink key id of the current primary signing key (the key used to sign new tokens).
     *
     * @return the primary signing key's Tink id
     */
    public int getPrimaryKeyId() {
        return keysetStore.getPrimaryKeyId();
    }

    private void registerIssuers() {
        String self = trustaProperties.getIssuer();
        boolean allowFetchPublicKeyThroughHTTP = trustaProperties.isAllowHttp();
        List<TrustedIssuer> trustedIssuers = trustaProperties.getTrustedIssuers();
        if (trustedIssuers.isEmpty()) {
            return;
        }
        for (TrustedIssuer trustedIssuer : trustedIssuers) {
            if (!StringUtils.hasText(trustedIssuer.getIssuer())) {
                throw new IllegalStateException("trusted-issuers[].issuer must not be blank");
            }
            if (trustedIssuer.getIdentifier() == null) {
                throw new IllegalStateException(
                        "trusted-issuers[].identifier is required for issuer: " + trustedIssuer.getIssuer());
            }
            JsonWebTokenVerify jsonWebTokenVerify = new JsonWebTokenVerify(
                    trustedIssuer, self, allowFetchPublicKeyThroughHTTP, objectMapper);
            verifyMap.put(trustedIssuer.getIssuer(), jsonWebTokenVerify);
        }
        // Do not prefetch public keys at startup; fetch on demand by kid / first verify.
    }
}
