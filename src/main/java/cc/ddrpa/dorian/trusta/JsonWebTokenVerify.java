package cc.ddrpa.dorian.trusta;

import cc.ddrpa.dorian.trusta.properties.TrustedIssuer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.VerifiedJwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * Verifies JWTs from a single trusted issuer.
 * <p>
 * Always validates {@code iss} and {@code aud}. Public keys are cached in memory and
 * refreshed on demand when the cache is empty/expired or the token {@code kid} is unknown.
 */
public class JsonWebTokenVerify {

    private static final Logger logger = LoggerFactory.getLogger(JsonWebTokenVerify.class);
    static final Duration DEFAULT_PUBLIC_KEY_CACHE_TTL = Duration.ofMinutes(3);
    private static final String DEFAULT_JWKS_PATH = "/.well-known/trusta-jwks.json";
    /**
     * After a refresh that failed to authenticate an unknown {@code kid} (or failed to fetch at all),
     * further unknown-kid/cold verifications fail fast without another refresh for this long.
     * This bounds the per-token refresh amplification; manual {@link #updatePublicKey()} always
     * bypasses the backoff.
     */
    static final Duration REFRESH_BACKOFF = Duration.ofSeconds(30);
    /**
     * Upper bound for the public keyset content accepted for parsing, regardless of how the content
     * was obtained (network fetch, injected string, ...). 256 KiB is far above any realistic keyset.
     */
    public static final int MAX_PUBLIC_KEYSET_BYTES = 256 * 1024;
    /** Upper bound for a JWT passed into verification paths (defense in depth against oversized input). */
    public static final int MAX_TOKEN_LENGTH = 16 * 1024;

    private final String issuer;
    private final URI publicKeyURI;
    private final JwtValidator jwtValidator;
    private final ObjectMapper objectMapper;
    private final Duration cacheTtl;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    private final Object lock = new Object();
    private volatile JwtPublicKeyVerify jwtPublicKeyVerify;
    private volatile Set<String> knownKids = Collections.emptySet();
    private volatile Instant cacheExpiresAt = Instant.EPOCH;
    private volatile Instant lastUpdateTime;
    private volatile Instant refreshBackoffUntil = Instant.EPOCH;
    private volatile CompletableFuture<Void> inFlightRefresh;

    /**
     * @param issuer                         trusted issuer configuration
     * @param self                           this system's issuer (expected audience)
     * @param allowFetchPublicKeyThroughHTTP whether HTTP (non-TLS) JWKS URIs are allowed
     * @param objectMapper                   JSON mapper for JWT header/keyset parsing
     */
    public JsonWebTokenVerify(TrustedIssuer issuer, String self, boolean allowFetchPublicKeyThroughHTTP,
                              ObjectMapper objectMapper) {
        this(issuer, self, allowFetchPublicKeyThroughHTTP, objectMapper, DEFAULT_PUBLIC_KEY_CACHE_TTL);
    }

    JsonWebTokenVerify(TrustedIssuer issuer, String self, boolean allowFetchPublicKeyThroughHTTP,
                       ObjectMapper objectMapper, Duration cacheTtl) {
        String issuerName = issuer.getIssuer();
        if (!StringUtils.hasText(issuerName)) {
            throw new IllegalArgumentException("trusted issuer name must not be blank");
        }
        if (!StringUtils.hasText(self)) {
            throw new IllegalArgumentException("trusta.issuer (self / expected audience) must not be blank");
        }
        this.issuer = issuerName;
        this.objectMapper = objectMapper;
        this.cacheTtl = cacheTtl;
        if (StringUtils.hasText(issuer.getPublicKeyUri())) {
            URI uri = URI.create(issuer.getPublicKeyUri());
            if (!allowFetchPublicKeyThroughHTTP && "http".equalsIgnoreCase(uri.getScheme())) {
                throw new IllegalArgumentException("HTTP URI scheme is not allowed for issuer: " + issuerName);
            }
            this.publicKeyURI = uri;
        } else {
            this.publicKeyURI = URI.create("https://" + issuerName + DEFAULT_JWKS_PATH);
        }
        this.jwtValidator = JwtValidator.newBuilder()
                .expectIssuer(issuerName)
                .expectAudience(self)
                .build();
    }

    public String getIssuer() {
        return issuer;
    }

    public Instant getLastUpdateTime() {
        return lastUpdateTime;
    }

    public boolean isReady() {
        return jwtPublicKeyVerify != null;
    }

    /**
     * Verify and decode a JWT from this issuer.
     */
    public VerifiedClaims verify(final String signedToken) throws GeneralSecurityException {
        if (signedToken.length() > MAX_TOKEN_LENGTH) {
            throw new IllegalArgumentException("JWT exceeds the maximum supported length of "
                    + MAX_TOKEN_LENGTH + " characters");
        }
        ensurePublicKey(signedToken);
        JwtPublicKeyVerify verifier = this.jwtPublicKeyVerify;
        if (verifier == null) {
            throw new IllegalStateException("Public key is not ready for issuer: " + issuer);
        }
        try {
            return decode(verifier, signedToken);
        } catch (GeneralSecurityException firstFailure) {
            String kid = extractKid(signedToken);
            if (kid != null && !knownKids.contains(kid)
                    && !Instant.now().isBefore(refreshBackoffUntil)) {
                // Unknown kid: at most one refresh per backoff window, then decode again.
                forceRefresh();
                verifier = this.jwtPublicKeyVerify;
                if (verifier == null) {
                    throw firstFailure;
                }
                try {
                    return decode(verifier, signedToken);
                } catch (GeneralSecurityException secondFailure) {
                    // Fresh keyset still lacks this kid: keep the backoff active.
                    markRefreshBackoff();
                    throw secondFailure;
                }
            }
            throw firstFailure;
        }
    }

    private VerifiedClaims decode(JwtPublicKeyVerify verifier, String signedToken) throws GeneralSecurityException {
        VerifiedJwt verifiedJwt = verifier.verifyAndDecode(signedToken, this.jwtValidator);
        return new VerifiedClaims()
                .setIssuer(verifiedJwt.getIssuer())
                .setSubject(verifiedJwt.getSubject());
    }

    /**
     * Force-refresh the public keyset from the configured URI.
     */
    public void updatePublicKey() throws GeneralSecurityException, IOException, InterruptedException {
        forceRefresh();
    }

    private void ensurePublicKey(String signedToken) throws GeneralSecurityException {
        String kid = extractKid(signedToken);
        Instant now = Instant.now();
        if (jwtPublicKeyVerify != null
                && now.isBefore(cacheExpiresAt)
                && (kid == null || knownKids.contains(kid))) {
            return;
        }
        if (jwtPublicKeyVerify == null) {
            // Cold start: always try once, but do not hammer a down issuer more than once per backoff.
            if (now.isBefore(refreshBackoffUntil)) {
                throw new GeneralSecurityException("Public key is not ready for issuer: " + issuer
                        + " (previous refresh attempt failed; next attempt allowed after "
                        + refreshBackoffUntil + ")");
            }
            forceRefresh();
            return;
        }
        // Cache expired: refresh when not currently backing off. Unknown kids are not refreshed
        // here; verify() performs the single refresh per backoff window, so a forged token triggers
        // at most one fetch per call.
        if (!now.isBefore(cacheExpiresAt)
                && (kid == null || knownKids.contains(kid))
                && !now.isBefore(refreshBackoffUntil)) {
            forceRefresh();
        }
    }

    private void markRefreshBackoff() {
        refreshBackoffUntil = Instant.now().plus(REFRESH_BACKOFF);
    }

    private void forceRefresh() throws GeneralSecurityException {
        CompletableFuture<Void> refresh;
        synchronized (lock) {
            if (inFlightRefresh != null) {
                refresh = inFlightRefresh;
            } else {
                refresh = CompletableFuture.runAsync(() -> {
                    try {
                        fetchAndApplyPublicKey();
                    } catch (Exception e) {
                        throw new CompletionException(e);
                    }
                });
                inFlightRefresh = refresh;
                refresh.whenComplete((ok, err) -> {
                    synchronized (lock) {
                        if (inFlightRefresh == refresh) {
                            inFlightRefresh = null;
                        }
                    }
                });
            }
        }
        try {
            refresh.join();
        } catch (CompletionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            markRefreshBackoff();
            if (jwtPublicKeyVerify != null) {
                logger.warn("Failed to refresh public key for issuer {}, keeping cached keyset: {}",
                        issuer, cause.getMessage());
                return;
            }
            if (cause instanceof GeneralSecurityException gse) {
                throw gse;
            }
            if (cause instanceof IOException ioe) {
                throw new GeneralSecurityException("Failed to fetch public key for issuer: " + issuer, ioe);
            }
            if (cause instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                throw new GeneralSecurityException("Interrupted while fetching public key for issuer: " + issuer, cause);
            }
            throw new GeneralSecurityException("Failed to fetch public key for issuer: " + issuer, cause);
        }
    }

    private void fetchAndApplyPublicKey() throws GeneralSecurityException, IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(publicKeyURI)
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to fetch public keyset from " + publicKeyURI
                    + ", status code: " + response.statusCode());
        }
        String publicKeysetAsString = response.body();
        if (publicKeysetAsString.length() > MAX_PUBLIC_KEYSET_BYTES) {
            throw new IOException("Public keyset content from " + publicKeyURI + " exceeds the maximum "
                    + "allowed size of " + MAX_PUBLIC_KEYSET_BYTES + " bytes");
        }
        KeysetHandle publicKeysetHandle = TinkJsonProtoKeysetFormat.parseKeyset(
                publicKeysetAsString, InsecureSecretKeyAccess.get());
        JwtPublicKeyVerify verify = publicKeysetHandle.getPrimitive(
                RegistryConfiguration.get(), JwtPublicKeyVerify.class);
        Set<String> kids = extractKidsFromKeyset(publicKeysetHandle);
        synchronized (lock) {
            this.jwtPublicKeyVerify = verify;
            this.knownKids = kids;
            this.lastUpdateTime = Instant.now();
            this.cacheExpiresAt = this.lastUpdateTime.plus(cacheTtl);
            this.refreshBackoffUntil = Instant.EPOCH;
        }
    }

    static Set<String> extractKidsFromKeyset(KeysetHandle publicKeysetHandle) {
        Set<String> kids = new HashSet<>();
        for (int i = 0; i < publicKeysetHandle.size(); i++) {
            KeysetHandle.Entry entry = publicKeysetHandle.getAt(i);
            if (entry.getStatus() == com.google.crypto.tink.KeyStatus.ENABLED) {
                kids.add(base64UrlKid(entry.getId()));
            }
        }
        return Collections.unmodifiableSet(kids);
    }

    /**
     * All payload claims as a string-valued map: strings stay as-is; numbers, booleans, arrays and
     * objects become their compact JSON text; {@code null} stays {@code null}.
     */
    static Map<String, String> toStringClaimsMap(JsonNode payloadNode) {
        Map<String, String> claims = new LinkedHashMap<>();
        for (Iterator<Map.Entry<String, JsonNode>> fields = payloadNode.fields(); fields.hasNext(); ) {
            Map.Entry<String, JsonNode> field = fields.next();
            JsonNode value = field.getValue();
            if (value.isNull()) {
                claims.put(field.getKey(), null);
            } else if (value.isTextual()) {
                claims.put(field.getKey(), value.asText());
            } else {
                claims.put(field.getKey(), value.toString());
            }
        }
        return claims;
    }

    static String base64UrlKid(int keyId) {
        byte[] bigEndianKeyId = ByteBuffer.allocate(4).putInt(keyId).array();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bigEndianKeyId);
    }

    String extractKid(String signedToken) {
        try {
            String[] parts = signedToken.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            JsonNode kidNode = objectMapper.readTree(headerJson).get("kid");
            return kidNode == null || kidNode.isNull() ? null : kidNode.asText();
        } catch (Exception e) {
            return null;
        }
    }
}
