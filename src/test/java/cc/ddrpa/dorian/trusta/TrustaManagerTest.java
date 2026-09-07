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
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

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

    private TrustaManager issuerOnly(String issuerName) throws Exception {
        StaticApplicationContext ctx = new StaticApplicationContext();
        ctx.refresh();
        TrustaProperties props = new TrustaProperties();
        props.setIssuer(issuerName);
        props.setPrivateKeysetFile(tempDir.resolve("issuer-" + issuerName + "-keyset").toString());
        props.setTrustedIssuers(List.of());
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
