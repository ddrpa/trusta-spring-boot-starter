package cc.ddrpa.dorian.trusta;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bootstraps a real servlet context (embedded Tomcat) so the auto-configuration runs end to end:
 * {@code TrustaManager} bean, the initialization runner (strategy binding + programmatic JWKS
 * mapping registration) and the actual GET {@code /.well-known/trusta-jwks.json} response.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "trusta.issuer=integration.example.cc",
                "trusta.private-keyset-file=target/integration-keyset.json"
        })
class TrustaAutoConfigurationTest {

    @SpringBootApplication
    @SpringBootConfiguration
    static class IntegrationTestApplication {
    }

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void jwksEndpointIsServedOverHttp() {
        ResponseEntity<String> response =
                restTemplate.getForEntity("/.well-known/trusta-jwks.json", String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("primaryKeyId"));
        assertTrue(response.getBody().contains("\"key\""));
    }
}
