package com.cloudiam.keycloak.pat;

import com.cloudiam.keycloak.pat.config.PatConstants;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.response.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;

import static com.cloudiam.keycloak.pat.TestConfig.getKeycloakDockerImage;
import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * On a Keycloak whose Admin API accepts tokens without its audience (here: the admin audience check turned off),
 * a token obtained with a PAT would carry all of its owner's admin rights, so the PAT grant must refuse every exchange.
 */
@Testcontainers
class PatAdminApiUnprotectedTest {

    @Container
    private static final KeycloakContainer KEYCLOAK_CONTAINER = new KeycloakContainer(getKeycloakDockerImage())
            .withAdminUsername("admin")
            .withAdminPassword("admin")
            .withStartupTimeout(Duration.ofSeconds(300))
            .withDefaultProviderClasses()
            .withEnv("KC_SPI_ADMIN__AUDIENCE_CHECK_ENABLED", "false");

    @Test
    @DisplayName("PAT exchange is refused when the Admin API audience check is disabled")
    void patExchangeRefusedWhenAdminApiUnprotected() {
        Response response = given()
                .baseUri(KEYCLOAK_CONTAINER.getAuthServerUrl())
                .formParam("grant_type", PatConstants.GRANT_TYPE)
                .formParam("client_id", "admin-cli")
                .formParam("pat", "pat_anything.anything")
                .post("/realms/master/protocol/openid-connect/token");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).isEqualTo("unsupported_grant_type");
        assertThat(response.jsonPath().getString("error_description")).contains("26.8.2");
        assertThat(KEYCLOAK_CONTAINER.getLogs()).contains("Personal Access Token exchange is DISABLED");
    }
}
