package cc.ddrpa.dorian.trusta;

import cc.ddrpa.dorian.trusta.properties.TrustaProperties;
import cc.ddrpa.dorian.trusta.properties.TrustedIssuer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.support.StaticApplicationContext;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustaManagerTest {

    @TempDir
    Path tempDir;

    private HttpServer httpServer;
    private final AtomicReference<String> jwksBody = new AtomicReference<>("{}");
    private final AtomicInteger jwksHits = new AtomicInteger();
    private String jwksUrl;
    private ObjectMapper objectMapper;

    @BeforeAll
    static void registerTink() throws GeneralSecurityException {
        JwtSignatureConfig.register();
    }

    @BeforeEach
    void startJwksServer() throws IOException {
        objectMapper = new ObjectMapper();
        httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpServer.createContext("/.well-known/trusta-jwks.json", exchange -> {
            jwksHits.incrementAndGet();
            byte[] body = jwksBody.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        httpServer.start();
        jwksUrl = "http://127.0.0.1:" + httpServer.getAddress().getPort() + "/.well-known/trusta-jwks.json";
    }

    @AfterEach
    void stopJwksServer() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
    }

    @Test
    void issueToRequiresAudienceAndSubject() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        assertThrows(IllegalStateException.class, () -> issuer.getSigner().setSubject("a@b.c").sign());
        assertThrows(IllegalStateException.class, () -> issuer.issueTo("audience.example.cc").sign());
        String token = issuer.issueTo("audience.example.cc").setSubject("a@b.c").sign();
        assertEquals(3, token.split("\\.").length);
        JsonNode header = objectMapper.readTree(new String(
                Base64.getUrlDecoder().decode(token.split("\\.")[0]), StandardCharsets.UTF_8));
        assertTrue(header.hasNonNull("kid"));
    }

    @Test
    void verifyAndResolveWithSharedStrategy() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        jwksBody.set(issuer.getPublicKeySetAsJSONString());

        EmailStrategy strategy = new EmailStrategy();
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.registerBean(EmailStrategy.class, () -> strategy);
        ctx.refresh();

        TrustaProperties receiverProps = new TrustaProperties();
        receiverProps.setIssuer("audience.example.cc");
        receiverProps.setPrivateKeysetFile(tempDir.resolve("receiver-keyset").toString());
        receiverProps.setAllowHttp(true);
        TrustedIssuer trusted = new TrustedIssuer()
                .setIssuer("issuer.example.cc")
                .setPublicKeyUri(jwksUrl)
                .setIdentifier(EmailStrategy.class);
        receiverProps.setTrustedIssuers(List.of(trusted));

        TrustaManager receiver = new TrustaManager(receiverProps, objectMapper, ctx);
        receiver.bindSubjectStrategies();

        String token = issuer.issueTo("audience.example.cc").setSubject("tom@example.com").sign();
        VerifiedClaims claims = receiver.verify(token);
        assertEquals("tom@example.com", claims.getSubject());
        assertEquals("issuer.example.cc", claims.getIssuer());

        String user = receiver.resolve(token);
        assertEquals("found:tom@example.com", user);
        assertEquals(1, jwksHits.get());

        // cache hit — no extra JWKS fetch
        receiver.verify(token);
        assertEquals(1, jwksHits.get());
    }

    @Test
    void verifiedClaimsExposeAllClaimsAsStrings() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        jwksBody.set(issuer.getPublicKeySetAsJSONString());
        TrustaManager receiver = receiverManager("receiver-claims", "issuer.example.cc", jwksUrl);
        String token = issuer.issueTo("audience.example.cc")
                .setSubject("tom@example.com")
                .addClaim("role", "admin")
                .sign();
        VerifiedClaims claims = receiver.verify(token);
        assertEquals("admin", claims.getClaims().get("role"));
        assertEquals("issuer.example.cc", claims.getClaims().get("iss"));
        assertEquals("audience.example.cc", claims.getClaims().get("aud"));
        assertEquals("tom@example.com", claims.getClaims().get("sub"));
        assertTrue(claims.getClaims().containsKey("exp"));
        assertThrows(UnsupportedOperationException.class,
                () -> claims.getClaims().put("x", "y"));
    }

    @Test
    void rotateSigningKeyPublishesNewKidAndOldTokenStillVerifies() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        int oldPrimary = issuer.getPrimaryKeyId();
        String oldToken = issuer.issueTo("audience.example.cc").setSubject("tom@example.com").sign();
        jwksBody.set(issuer.getPublicKeySetAsJSONString());

        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.registerBean(EmailStrategy.class, EmailStrategy::new);
        ctx.refresh();

        TrustaProperties receiverProps = new TrustaProperties();
        receiverProps.setIssuer("audience.example.cc");
        receiverProps.setPrivateKeysetFile(tempDir.resolve("receiver-keyset-2").toString());
        receiverProps.setAllowHttp(true);
        receiverProps.setTrustedIssuers(List.of(new TrustedIssuer()
                .setIssuer("issuer.example.cc")
                .setPublicKeyUri(jwksUrl)
                .setIdentifier(EmailStrategy.class)));
        TrustaManager receiver = new TrustaManager(receiverProps, objectMapper, ctx);
        receiver.bindSubjectStrategies();
        assertEquals("tom@example.com", receiver.verify(oldToken).getSubject());

        int newPrimary = issuer.rotateSigningKey();
        assertNotEquals(oldPrimary, newPrimary);
        jwksBody.set(issuer.getPublicKeySetAsJSONString());

        String newToken = issuer.issueTo("audience.example.cc").setSubject("tom@example.com").sign();
        String newKid = objectMapper.readTree(new String(
                Base64.getUrlDecoder().decode(newToken.split("\\.")[0]), StandardCharsets.UTF_8)).get("kid").asText();
        String oldKid = objectMapper.readTree(new String(
                Base64.getUrlDecoder().decode(oldToken.split("\\.")[0]), StandardCharsets.UTF_8)).get("kid").asText();
        assertNotEquals(oldKid, newKid);

        // unknown kid triggers refresh
        assertEquals("tom@example.com", receiver.verify(newToken).getSubject());
        // old key still enabled — old token still verifies after refresh
        assertEquals("tom@example.com", receiver.verify(oldToken).getSubject());

        issuer.disableSigningKey(oldPrimary);
        jwksBody.set(issuer.getPublicKeySetAsJSONString());
        // force cache expiry path by manual refresh
        receiver.updateIssuerPublicKey();
        assertEquals("tom@example.com", receiver.verify(newToken).getSubject());
        assertThrows(GeneralSecurityException.class, () -> receiver.verify(oldToken));
    }

    @Test
    void silentRegisterOptional() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        jwksBody.set(issuer.getPublicKeySetAsJSONString());

        RegisteringStrategy strategy = new RegisteringStrategy();
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.registerBean(RegisteringStrategy.class, () -> strategy);
        ctx.refresh();

        TrustaProperties receiverProps = new TrustaProperties();
        receiverProps.setIssuer("audience.example.cc");
        receiverProps.setPrivateKeysetFile(tempDir.resolve("receiver-keyset-3").toString());
        receiverProps.setAllowHttp(true);
        receiverProps.setTrustedIssuers(List.of(new TrustedIssuer()
                .setIssuer("issuer.example.cc")
                .setPublicKeyUri(jwksUrl)
                .setIdentifier(RegisteringStrategy.class)));
        TrustaManager receiver = new TrustaManager(receiverProps, objectMapper, ctx);
        receiver.bindSubjectStrategies();

        String token = issuer.issueTo("audience.example.cc").setSubject("new@example.com").sign();
        assertEquals("created:new@example.com", receiver.resolve(token));
    }

    @Test
    void defaultTokenValidityIs30Seconds() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        String token = issuer.issueTo("audience.example.cc").setSubject("a@b.c").sign();
        assertEquals(30, numericClaim(token, "exp") - numericClaim(token, "iat"));
    }

    @Test
    void configuredTokenValidityOverridesDefault() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc",
                props -> props.setTokenValidity(120));
        String token = issuer.issueTo("audience.example.cc").setSubject("a@b.c").sign();
        assertEquals(120, numericClaim(token, "exp") - numericClaim(token, "iat"));
    }

    @Test
    void perSignerValidityOverridesDefaultAndBoundsAreEnforced() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        String token = issuer.issueTo("audience.example.cc").setSubject("a@b.c")
                .setValidityPeriod(Duration.ofMinutes(5))
                .sign();
        assertEquals(300, numericClaim(token, "exp") - numericClaim(token, "iat"));
        // zero / negative / beyond the cap are rejected
        assertThrows(IllegalArgumentException.class, () -> issuer.issueTo("audience.example.cc")
                .setValidityPeriod(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> issuer.issueTo("audience.example.cc")
                .setValidityPeriod(Duration.ofMinutes(-1)));
        assertThrows(IllegalArgumentException.class, () -> issuer.issueTo("audience.example.cc")
                .setValidityPeriod(JsonWebTokenSigner.MAX_VALIDITY_PERIOD.plusSeconds(1)));
    }

    @Test
    void invalidConfiguredTokenValidityFailsFast() {
        // 0 / negative / beyond the 600s cap are rejected at startup
        assertThrows(IllegalArgumentException.class, () -> issuerOnly("issuer.example.cc",
                props -> props.setTokenValidity(0)));
        assertThrows(IllegalArgumentException.class, () -> issuerOnly("issuer.example.cc",
                props -> props.setTokenValidity(-1)));
        assertThrows(IllegalArgumentException.class, () -> issuerOnly("issuer.example.cc",
                props -> props.setTokenValidity(601)));
    }

    @Test
    void blankIssuerFailsFastAtStartup() {
        TrustaProperties props = new TrustaProperties();
        props.setIssuer("");
        props.setPrivateKeysetFile(tempDir.resolve("blank-issuer-keyset").toString());
        props.setTrustedIssuers(List.of());
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.refresh();
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new TrustaManager(props, objectMapper, ctx));
        assertTrue(e.getMessage().contains("trusta.issuer"));
    }

    @Test
    void missingKeysetIsGeneratedOnStartup() throws Exception {
        Path keyset = tempDir.resolve("auto-created-keyset");
        TrustaProperties props = new TrustaProperties();
        props.setIssuer("issuer.example.cc");
        props.setPrivateKeysetFile(keyset.toString());
        props.setTrustedIssuers(List.of());
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.refresh();
        new TrustaManager(props, objectMapper, ctx);
        assertTrue(Files.exists(keyset));
    }

    @Test
    void autoGeneratedKeysetIsOwnerOnly() throws Exception {
        Path keyset = tempDir.resolve("owner-only-keyset");
        TrustaProperties props = new TrustaProperties();
        props.setIssuer("issuer.example.cc");
        props.setPrivateKeysetFile(keyset.toString());
        props.setTrustedIssuers(List.of());
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.refresh();
        new TrustaManager(props, objectMapper, ctx);
        assertTrue(Files.exists(keyset));
        if (keyset.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            assertEquals(
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(keyset));
        }
    }

    @Test
    void unknownKidRefreshIsBackedOff() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        jwksBody.set(issuer.getPublicKeySetAsJSONString());
        TrustaManager receiver = receiverManager("receiver-backoff", "issuer.example.cc", jwksUrl);
        String token = issuer.issueTo("audience.example.cc").setSubject("a@b.c").sign();
        receiver.verify(token);
        assertEquals(1, jwksHits.get());

        // First forged token with an unknown kid triggers exactly one refresh...
        assertThrows(GeneralSecurityException.class,
                () -> receiver.verify(forgedTokenWithKid("Zm9yZ2VkLWtpZC0x")));
        assertEquals(2, jwksHits.get());
        // ...but the backoff makes subsequent forged tokens fail fast without another fetch.
        assertThrows(GeneralSecurityException.class,
                () -> receiver.verify(forgedTokenWithKid("Zm9yZ2VkLWtpZC0y")));
        assertEquals(2, jwksHits.get());
    }

    @Test
    void oversizedJwtIsRejectedBeforeAnyFetch() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        jwksBody.set(issuer.getPublicKeySetAsJSONString());
        TrustaManager receiver = receiverManager("receiver-len", "issuer.example.cc", jwksUrl);
        String hugeHeader = base64Url("a".repeat(JsonWebTokenVerify.MAX_TOKEN_LENGTH));
        String oversized = hugeHeader + "." + base64Url("{}") + ".c2ln";
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> receiver.verify(oversized));
        assertTrue(e.getMessage().contains("maximum supported length"));
        assertEquals(0, jwksHits.get());
    }

    @Test
    void oversizedPublicKeysetContentIsRejected() throws Exception {
        TrustaManager issuer = issuerOnly("issuer.example.cc");
        jwksBody.set("x".repeat(JsonWebTokenVerify.MAX_PUBLIC_KEYSET_BYTES + 1));
        TrustaManager receiver = receiverManager("receiver-huge", "issuer.example.cc", jwksUrl);
        String token = issuer.issueTo("audience.example.cc").setSubject("a@b.c").sign();
        assertThrows(GeneralSecurityException.class, () -> receiver.verify(token));
        assertEquals(1, jwksHits.get());
    }

    private TrustaManager receiverManager(String keysetName, String trustedIssuer, String jwksUri)
            throws Exception {
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.registerBean(EmailStrategy.class, EmailStrategy::new);
        ctx.refresh();
        TrustaProperties receiverProps = new TrustaProperties();
        receiverProps.setIssuer("audience.example.cc");
        receiverProps.setPrivateKeysetFile(tempDir.resolve(keysetName).toString());
        receiverProps.setAllowHttp(true);
        receiverProps.setTrustedIssuers(List.of(new TrustedIssuer()
                .setIssuer(trustedIssuer)
                .setPublicKeyUri(jwksUri)
                .setIdentifier(EmailStrategy.class)));
        return new TrustaManager(receiverProps, objectMapper, ctx);
    }

    private static String forgedTokenWithKid(String kid) {
        String header = "{\"alg\":\"ES256\",\"kid\":\"" + kid + "\"}";
        String payload = "{\"iss\":\"issuer.example.cc\"}";
        return base64Url(header) + "." + base64Url(payload) + ".c2ln";
    }

    private static String base64Url(String raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                raw.getBytes(StandardCharsets.UTF_8));
    }

    private long numericClaim(String token, String claim) throws Exception {
        String payloadJson = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]),
                StandardCharsets.UTF_8);
        return objectMapper.readTree(payloadJson).get(claim).asLong();
    }

    private TrustaManager issuerOnly(String issuerName) throws Exception {
        return issuerOnly(issuerName, props -> { });
    }

    private TrustaManager issuerOnly(String issuerName, Consumer<TrustaProperties> customizer) throws Exception {
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.refresh();
        TrustaProperties props = new TrustaProperties();
        props.setIssuer(issuerName);
        props.setPrivateKeysetFile(tempDir.resolve("issuer-" + issuerName + "-keyset").toString());
        props.setTrustedIssuers(List.of());
        customizer.accept(props);
        return new TrustaManager(props, objectMapper, ctx);
    }

    static class EmailStrategy implements SubjectStrategy<String> {
        @Override
        public Optional<String> find(String subject, VerifiedClaims claims) {
            return Optional.of("found:" + subject);
        }
    }

    static class RegisteringStrategy implements SubjectStrategy<String> {
        @Override
        public Optional<String> find(String subject, VerifiedClaims claims) {
            return Optional.empty();
        }

        @Override
        public String register(String subject, VerifiedClaims claims) {
            return "created:" + subject;
        }
    }
}
