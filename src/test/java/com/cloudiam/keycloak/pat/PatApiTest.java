package com.cloudiam.keycloak.pat;

import com.cloudiam.keycloak.pat.config.PatConstants;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.jacoco.core.tools.ExecDumpClient;
import org.jacoco.core.tools.ExecFileLoader;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.cloudiam.keycloak.pat.TestConfig.REALM;
import static com.cloudiam.keycloak.pat.TestConfig.getKeycloakDockerImage;
import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.slf4j.LoggerFactory.getLogger;

@Testcontainers
class PatApiTest {

    private static final Logger LOGGER = getLogger(PatApiTest.class);

    private static final String GRANT_TYPE = PatConstants.GRANT_TYPE;
    private static final int KEYCLOAK_HTTP_PORT = 8080;
    private static final int KEYCLOAK_METRICS_HTTP_PORT = 9000;
    private static final Network NETWORK = Network.newNetwork();

    @Container
    private static final KeycloakContainer KEYCLOAK_CONTAINER = new KeycloakContainer(getKeycloakDockerImage())
            .withAdminUsername("admin")
            .withAdminPassword("admin")
            .withLogConsumer(new Slf4jLogConsumer(LOGGER).withSeparateOutputStreams())
            .withExposedPorts(KEYCLOAK_HTTP_PORT, KEYCLOAK_METRICS_HTTP_PORT, 6300)
            .withStartupTimeout(Duration.ofSeconds(300))
            .withNetwork(NETWORK)
            .withNetworkAliases("keycloak")
            .withDefaultProviderClasses()
            .withRealmImportFile("realm-export.json")
            .withFileSystemBind("target/jacoco-agent", "/jacoco-agent", BindMode.READ_WRITE)
            .withEnv("JAVA_OPTS_APPEND", "-javaagent:/jacoco-agent/org.jacoco.agent-runtime.jar=output=tcpserver,address=*,port=6300,dumponexit=false,destfile=/jacoco-agent/jacoco.exec")
            .withEnv("KC_LOG_LEVEL", "INFO,com.cloudiam:TRACE");

    @BeforeAll
    static void setUp() {
        RestAssured.baseURI = getKeycloakBaseUrl();
        LOGGER.info("Keycloak base URL: {}", RestAssured.baseURI);
    }

    @AfterAll
    static void tearDown() throws IOException {
        ExecDumpClient jacocoClient = new ExecDumpClient();
        ExecFileLoader dump = jacocoClient.dump(KEYCLOAK_CONTAINER.getHost(), KEYCLOAK_CONTAINER.getMappedPort(6300));
        dump.save(new File("./target/jacoco-agent/jacoco.exec"), true);

        NETWORK.close();
        KEYCLOAK_CONTAINER.stop();
    }

    // ========== PAT Creation Tests ==========

    @Test
    @DisplayName("Should create a PAT for a user with roles")
    void shouldCreatePatForUserWithRoles() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "CI/CD Token",
                        "expirationDays", 90,
                        "roles", List.of("test-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        LOGGER.info("Create PAT response: {} - {}", response.statusCode(), response.body().asString());

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getString("id")).isNotEmpty();
        assertThat(response.jsonPath().getString("name")).isEqualTo("CI/CD Token");
        assertThat(response.jsonPath().getString("token")).startsWith("pat_");
        assertThat(response.jsonPath().getList("roles")).containsExactly("test-role");
        assertThat(response.jsonPath().getString("createdAt")).isNotNull();
        assertThat(response.jsonPath().getString("expiresAt")).isNotNull();
    }

    @Test
    @DisplayName("Should create a PAT with expiration")
    void shouldCreatePatWithExpiration() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Short-lived Token",
                        "expirationDays", 30
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getString("expiresAt")).isNotNull();
        assertThat(response.jsonPath().getString("token")).startsWith("pat_");
    }

    @Test
    @DisplayName("Should create a PAT without expiration")
    void shouldCreatePatWithoutExpiration() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body("{\"name\": \"Permanent Token\", \"expirationDays\": null}")
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getString("expiresAt")).isNull();
        assertThat(response.jsonPath().getString("token")).startsWith("pat_");
    }

    @Test
    @DisplayName("Should expire after 90 days when expirationDays is omitted")
    void shouldDefaultTo90DaysExpiration() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Default Expiration Token"))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(201);
        Instant expiresAt = Instant.ofEpochSecond((long) response.jsonPath().getDouble("expiresAt"));
        assertThat(expiresAt).isBetween(
                Instant.now().plus(89, ChronoUnit.DAYS), Instant.now().plus(91, ChronoUnit.DAYS));
    }

    @Test
    @DisplayName("Should create a PAT with empty roles list")
    void shouldCreatePatWithEmptyRoles() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "No Roles Token",
                        "roles", Collections.emptyList()
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getList("roles")).isEmpty();
    }

    @Test
    @DisplayName("Should create multiple PATs for the same user")
    void shouldCreateMultiplePatsForSameUser() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response1 = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Token One"
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        Response response2 = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Token Two"
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response1.statusCode()).isEqualTo(201);
        assertThat(response2.statusCode()).isEqualTo(201);

        String id1 = response1.jsonPath().getString("id");
        String id2 = response2.jsonPath().getString("id");
        assertThat(id1).isNotEqualTo(id2);

        String token1 = response1.jsonPath().getString("token");
        String token2 = response2.jsonPath().getString("token");
        assertThat(token1).isNotEqualTo(token2);
    }

    // ========== Validation Error Tests ==========

    @Test
    @DisplayName("Should reject PAT creation without name")
    void shouldRejectPatWithoutName() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of())
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("name");
    }

    @Test
    @DisplayName("Should reject PAT creation with more than 50 roles")
    void shouldRejectPatWithTooManyRoles() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Too Many Roles Token",
                        "roles", Collections.nCopies(PatConstants.MAX_ROLES_PER_PAT + 1, "test-role")))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("roles must not exceed");
    }

    @Test
    @DisplayName("Should store each role once")
    void shouldDeduplicateRoles() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Duplicate Roles Token", "roles", List.of("test-role", " test-role", "test-role")))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getList("roles")).containsExactly("test-role");
    }

    @Test
    @DisplayName("Should reject PAT creation with non-existent role")
    void shouldRejectPatWithNonExistentRole() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Bad Role Token",
                        "roles", List.of("non-existent-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("Role not found");
    }

    @Test
    @DisplayName("Should reject PAT creation with role user does not have")
    void shouldRejectPatWithRoleUserDoesNotHave() {
        String realmToken = getRealmUserToken("christina", "admin");

        // christina has test-role but NOT admin-role
        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Wrong Role Token",
                        "roles", List.of("admin-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("User does not have role");
    }

    @Test
    @DisplayName("Should reject PAT creation with excessive expiration")
    void shouldRejectPatWithExcessiveExpiration() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Too Long Token",
                        "expirationDays", 500
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("365");
    }

    @Test
    @DisplayName("Should reject PAT creation with duplicate name")
    void shouldRejectPatWithDuplicateName() {
        String realmToken = getRealmUserToken("christina", "admin");

        String patName = "Unique Duplicate Test Token";

        // First creation should succeed
        Response first = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", patName
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(first.statusCode()).isEqualTo(201);

        // Second creation with the same name should fail
        Response second = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", patName
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(second.statusCode()).isEqualTo(400);
        assertThat(second.jsonPath().getString("error")).contains("already exists");
    }

    @Test
    @DisplayName("Should reject PAT creation with name exceeding max length")
    void shouldRejectPatWithNameExceedingMaxLength() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Build a name longer than 255 characters
        String longName = "A".repeat(256);

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", longName
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("255");
    }

    @Test
    @DisplayName("Should reject PAT creation with control characters in name")
    void shouldRejectPatWithControlCharactersInName() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Token\nwith\nnewlines"
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("control characters");
    }

    @Test
    @DisplayName("Should accept PAT name with special characters (slash, parens, accents)")
    void shouldAcceptPatNameWithSpecialCharacters() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "CI/CD (Production) - v2.1"
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getString("name")).isEqualTo("CI/CD (Production) - v2.1");
    }

    @Test
    @DisplayName("Should trim whitespace from PAT name")
    void shouldTrimWhitespaceFromPatName() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "  Trimmed Token  "
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getString("name")).isEqualTo("Trimmed Token");
    }

    // ========== Authentication Tests ==========

    @Test
    @DisplayName("Should reject unauthenticated request")
    void shouldRejectUnauthenticatedRequest() {
        Response response = given()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "userId", "some-id",
                        "name", "Token"
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isIn(401, 403);
    }

    // ========== Grant Type Authentication Tests ==========

    @Test
    @DisplayName("Should authenticate with PAT grant type and return access token")
    void shouldAuthenticateWithPatGrantType() {
        // Create a PAT
        String realmToken = getRealmUserToken("christina", "admin");

        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Grant Type Test Token",
                        "expirationDays", 90,
                        "roles", List.of("test-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String patToken = createResponse.jsonPath().getString("token");
        assertThat(patToken).startsWith("pat_");

        // Authenticate using the PAT grant type
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", patToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        LOGGER.info("Grant type response: {} - {}", tokenResponse.statusCode(), tokenResponse.body().asString());

        assertThat(tokenResponse.statusCode()).isEqualTo(200);
        assertThat(tokenResponse.jsonPath().getString("access_token")).isNotEmpty();
        assertThat(tokenResponse.jsonPath().getString("token_type")).isEqualToIgnoringCase("Bearer");
        assertThat(tokenResponse.jsonPath().getInt("expires_in")).isGreaterThan(0);
    }

    @Test
    @DisplayName("Should include PAT roles in access token claims")
    void shouldIncludePatRolesInAccessToken() {
        // Create a PAT with roles
        String realmToken = getRealmUserToken("christina", "admin");

        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Roles Grant Token",
                        "roles", List.of("test-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String patToken = createResponse.jsonPath().getString("token");

        // Authenticate via grant type
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", patToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode()).isEqualTo(200);

        // Decode the JWT and verify claims
        String accessToken = tokenResponse.jsonPath().getString("access_token");
        String[] parts = accessToken.split("\\.");
        assertThat(parts).hasSize(3);

        // Decode the payload (second part)
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        LOGGER.info("JWT payload: {}", payload);

        // Verify PAT-specific claims
        assertThat(payload).contains("\"grant_type\":\"" + GRANT_TYPE + "\"");
        assertThat(payload).contains("\"preferred_username\":\"christina\"");
        assertThat(payload).contains("\"pat_name\":\"Roles Grant Token\"");
        assertThat(payload).contains("\"pat_id\"");
        // Verify roles are present in realm_access
        assertThat(payload).contains("\"realm_access\"");
        assertThat(payload).contains("test-role");
    }

    @Test
    @DisplayName("Should authenticate with PAT without roles")
    void shouldAuthenticateWithPatWithoutRoles() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "No Roles Grant Token"
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String patToken = createResponse.jsonPath().getString("token");

        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", patToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode()).isEqualTo(200);
        assertThat(tokenResponse.jsonPath().getString("access_token")).isNotEmpty();
        assertThat(tokenResponse.jsonPath().getString("token_type")).isEqualToIgnoringCase("Bearer");
    }

    @Test
    @DisplayName("Should reject grant type with invalid PAT value")
    void shouldRejectGrantTypeWithInvalidPat() {
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", "pat_invalid_token_value_that_does_not_exist")
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        LOGGER.info("Invalid PAT grant response: {} - {}", tokenResponse.statusCode(), tokenResponse.body().asString());

        assertThat(tokenResponse.statusCode()).isEqualTo(400);
        assertThat(tokenResponse.jsonPath().getString("error")).isNotEmpty();
    }

    @Test
    @DisplayName("Should reject grant type with missing PAT parameter")
    void shouldRejectGrantTypeWithMissingPat() {
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode()).isEqualTo(400);
        assertThat(tokenResponse.jsonPath().getString("error")).isNotEmpty();
    }

    @Test
    @DisplayName("Should reject grant type with empty PAT parameter")
    void shouldRejectGrantTypeWithEmptyPat() {
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", "")
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode()).isEqualTo(400);
        assertThat(tokenResponse.jsonPath().getString("error")).isNotEmpty();
    }

    // ========== Client Roles Tests ==========

    @Test
    @DisplayName("Should create a PAT with client roles")
    void shouldCreatePatWithClientRoles() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Client Role Token",
                        "expirationDays", 90,
                        "roles", List.of("test-app:editor")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        LOGGER.info("Create PAT with client roles response: {} - {}", response.statusCode(), response.body().asString());

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getString("token")).startsWith("pat_");
        assertThat(response.jsonPath().getList("roles")).containsExactly("test-app:editor");
    }

    @Test
    @DisplayName("Should create a PAT with mixed realm and client roles")
    void shouldCreatePatWithMixedRoles() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Mixed Roles Token",
                        "roles", List.of("test-role", "test-app:editor")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        LOGGER.info("Create PAT with mixed roles response: {} - {}", response.statusCode(), response.body().asString());

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getList("roles")).containsExactlyInAnyOrder("test-role", "test-app:editor");
    }

    @Test
    @DisplayName("Should include client roles in JWT resource_access via grant type")
    void shouldIncludeClientRolesInJwtResourceAccess() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create PAT with mixed realm + client roles
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "JWT Client Roles Token",
                        "roles", List.of("test-role", "test-app:editor")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String patToken = createResponse.jsonPath().getString("token");

        // Authenticate via grant type
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", patToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode()).isEqualTo(200);

        // Decode JWT and verify resource_access
        String accessToken = tokenResponse.jsonPath().getString("access_token");
        String[] parts = accessToken.split("\\.");
        assertThat(parts).hasSize(3);

        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        LOGGER.info("JWT payload with client roles: {}", payload);

        // Verify realm_access contains test-role
        assertThat(payload).contains("\"realm_access\"");
        assertThat(payload).contains("test-role");

        // Verify resource_access contains test-app with editor role
        assertThat(payload).contains("\"resource_access\"");
        assertThat(payload).contains("\"test-app\"");
        assertThat(payload).contains("editor");

        // Verify pat_roles contains both
        assertThat(payload).contains("\"pat_roles\"");
        assertThat(payload).contains("test-app:editor");
    }

    @Test
    @DisplayName("Should reject PAT creation with non-existent client in role")
    void shouldRejectPatWithNonExistentClient() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Bad Client Token",
                        "roles", List.of("non-existent-client:some-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("Role not found");
    }

    @Test
    @DisplayName("Should reject PAT creation with client role user does not have")
    void shouldRejectPatWithClientRoleUserDoesNotHave() {
        String realmToken = getRealmUserToken("christina", "admin");

        // christina has test-app:editor but NOT test-app:viewer
        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Wrong Client Role Token",
                        "roles", List.of("test-app:viewer")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).contains("User does not have role");
    }

    // ========== PAT Rotation Tests ==========

    @Test
    @DisplayName("Should rotate PAT and return new token")
    void shouldRotatePatAndReturnNewToken() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create a PAT
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Rotation Test Token",
                        "expirationDays", 90,
                        "roles", List.of("test-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String originalToken = createResponse.jsonPath().getString("token");
        String credentialId = createResponse.jsonPath().getString("id");

        // Rotate the PAT
        Response rotateResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of())
                .when()
                .post("/realms/" + REALM + "/pat/" + credentialId + "/rotate");

        LOGGER.info("Rotate PAT response: {} - {}", rotateResponse.statusCode(), rotateResponse.body().asString());

        assertThat(rotateResponse.statusCode()).isEqualTo(200);
        String newToken = rotateResponse.jsonPath().getString("token");
        assertThat(newToken).startsWith("pat_");
        assertThat(newToken).isNotEqualTo(originalToken);
        assertThat(rotateResponse.jsonPath().getString("id")).isEqualTo(credentialId);
        assertThat(rotateResponse.jsonPath().getString("name")).isEqualTo("Rotation Test Token");
        assertThat(rotateResponse.jsonPath().getList("roles")).containsExactly("test-role");
    }

    @Test
    @DisplayName("Should authenticate with new token after rotation")
    void shouldAuthenticateWithNewTokenAfterRotation() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create a PAT
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Auth After Rotation Token",
                        "expirationDays", 90,
                        "roles", List.of("test-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String credentialId = createResponse.jsonPath().getString("id");

        // Rotate the PAT
        Response rotateResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of())
                .when()
                .post("/realms/" + REALM + "/pat/" + credentialId + "/rotate");

        assertThat(rotateResponse.statusCode()).isEqualTo(200);
        String newToken = rotateResponse.jsonPath().getString("token");

        // Authenticate with the new token
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", newToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode()).isEqualTo(200);
        assertThat(tokenResponse.jsonPath().getString("access_token")).isNotEmpty();
    }

    @Test
    @DisplayName("Should reject old token after rotation")
    void shouldRejectOldTokenAfterRotation() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create a PAT
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Old Token Reject Test",
                        "expirationDays", 90,
                        "roles", List.of("test-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String oldToken = createResponse.jsonPath().getString("token");
        String credentialId = createResponse.jsonPath().getString("id");

        // Rotate the PAT
        Response rotateResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of())
                .when()
                .post("/realms/" + REALM + "/pat/" + credentialId + "/rotate");

        assertThat(rotateResponse.statusCode()).isEqualTo(200);

        // Try to authenticate with the OLD token - should fail
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", oldToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        LOGGER.info("Old token after rotation response: {} - {}", tokenResponse.statusCode(), tokenResponse.body().asString());

        assertThat(tokenResponse.statusCode()).isEqualTo(400);
        assertThat(tokenResponse.jsonPath().getString("error")).isNotEmpty();
    }

    @Test
    @DisplayName("Should rotate PAT with new expiration")
    void shouldRotatePatWithNewExpiration() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create a PAT with 30-day expiration
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Expiration Rotation Token",
                        "expirationDays", 30
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String credentialId = createResponse.jsonPath().getString("id");
        String originalExpiresAt = createResponse.jsonPath().getString("expiresAt");

        // Rotate with new 180-day expiration
        Response rotateResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("expirationDays", 180
                ))
                .when()
                .post("/realms/" + REALM + "/pat/" + credentialId + "/rotate");

        assertThat(rotateResponse.statusCode()).isEqualTo(200);
        String newExpiresAt = rotateResponse.jsonPath().getString("expiresAt");
        assertThat(newExpiresAt).isNotEqualTo(originalExpiresAt);
    }

    @Test
    @DisplayName("Should reject rotation for non-existent credential")
    void shouldRejectRotationForNonExistentCredential() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of())
                .when()
                .post("/realms/" + REALM + "/pat/non-existent-id/rotate");

        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.jsonPath().getString("error")).contains("PAT not found");
    }

    // ========== Authorization Tests ==========

    @Test
    @DisplayName("Should reject a request naming a user, since the API only manages the caller's PATs")
    void shouldRejectRequestNamingUser() {
        String christinaToken = getRealmUserToken("christina", "admin");
        String hannaId = getUserId("hanna");

        Response create = given()
                .header("Authorization", "Bearer " + christinaToken)
                .contentType(ContentType.JSON)
                .body(Map.of("userId", hannaId, "name", "Not For Hanna Token"))
                .when()
                .post("/realms/" + REALM + "/pat");
        assertThat(create.statusCode()).isEqualTo(400);
        assertThat(getPatCredentials(hannaId)).noneMatch(c -> "Not For Hanna Token".equals(c.get("userLabel")));
        assertThat(getPatCredentials(getUserId("christina"))).noneMatch(c -> "Not For Hanna Token".equals(c.get("userLabel")));

        Response rotate = given()
                .header("Authorization", "Bearer " + christinaToken)
                .contentType(ContentType.JSON)
                .body(Map.of("userId", hannaId))
                .when()
                .post("/realms/" + REALM + "/pat/any-id/rotate");
        assertThat(rotate.statusCode()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should allow user to create PAT for themselves")
    void shouldAllowUserToCreatePatForThemselves() {
        // hanna creates a PAT for herself - should work
        String hannaToken = getRealmUserToken("hanna", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + hannaToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Hanna Self Token",
                        "expirationDays", 30
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        LOGGER.info("Self PAT creation response: {} - {}", response.statusCode(), response.body().asString());

        assertThat(response.statusCode()).isEqualTo(201);
        assertThat(response.jsonPath().getString("token")).startsWith("pat_");
        assertThat(response.jsonPath().getString("name")).isEqualTo("Hanna Self Token");
    }

    @Test
    @DisplayName("Should not let a user rotate another user's PAT")
    void shouldNotRotateAnotherUsersPat() {
        String christinaToken = getRealmUserToken("christina", "admin");

        Response createResponse = given()
                .header("Authorization", "Bearer " + christinaToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Rotation Auth Test Token"))
                .when()
                .post("/realms/" + REALM + "/pat");
        assertThat(createResponse.statusCode()).isEqualTo(201);
        String credentialId = createResponse.jsonPath().getString("id");
        String token = createResponse.jsonPath().getString("token");

        // hanna names christina's PAT: it is not one of hers, so it does not exist for her
        Response rotateResponse = given()
                .header("Authorization", "Bearer " + getRealmUserToken("hanna", "admin"))
                .contentType(ContentType.JSON)
                .body(Map.of())
                .when()
                .post("/realms/" + REALM + "/pat/" + credentialId + "/rotate");

        assertThat(rotateResponse.statusCode()).isEqualTo(404);
        assertThat(exchangePat(token).statusCode()).isEqualTo(200);
    }

    // ========== Rate Limiting Tests ==========

    @Test
    @DisplayName("Should reject PAT creation when user exceeds maximum PAT limit")
    void shouldRejectPatCreationWhenExceedingLimit() {
        // A user of its own: the other tests' users must stay under the limit
        String userId = createTestUser("pat-limit-user");
        try {
            String token = getRealmUserToken("pat-limit-user", "admin");
            for (int i = 0; i <= PatConstants.MAX_PATS_PER_USER; i++) {
                Response response = given()
                        .header("Authorization", "Bearer " + token)
                        .contentType(ContentType.JSON)
                        .body(Map.of("name", "Limit Test Token " + i, "expirationDays", 30))
                        .when()
                        .post("/realms/" + REALM + "/pat");
                if (i < PatConstants.MAX_PATS_PER_USER) {
                    assertThat(response.statusCode()).isEqualTo(201);
                } else {
                    assertThat(response.statusCode()).isEqualTo(400);
                    assertThat(response.jsonPath().getString("error")).contains("Maximum number of PATs");
                }
            }
        } finally {
            deleteTestUser(userId);
        }
    }

    @Test
    @DisplayName("Should reject PAT grant when the user is disabled, and accept it again once re-enabled")
    void shouldRejectPatGrantWhenUserIsDisabled() {
        // Dedicated user, so disabling it cannot affect other tests
        String masterToken = getMasterAdminToken();
        Response created = given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "username", "disabled-pat-user",
                        "enabled", true,
                        "email", "disabled-pat-user@test.com",
                        "firstName", "Disabled",
                        "lastName", "User",
                        "emailVerified", true,
                        "credentials", List.of(Map.of("type", "password", "value", "admin", "temporary", false))
                ))
                .when()
                .post("/admin/realms/" + REALM + "/users");
        assertThat(created.statusCode()).isEqualTo(201);
        String userId = getUserId("disabled-pat-user");

        String pat = given()
                .header("Authorization", "Bearer " + getRealmUserToken("disabled-pat-user", "admin"))
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Disabled User Token", "expirationDays", 30))
                .when()
                .post("/realms/" + REALM + "/pat")
                .then().statusCode(201)
                .extract().jsonPath().getString("token");

        // Enabled: the PAT works
        assertThat(exchangePat(pat).statusCode()).isEqualTo(200);

        // Disabled: the PAT is refused, like a password login would be
        setUserEnabled(userId, false);
        Response refused = exchangePat(pat);
        LOGGER.info("PAT grant for disabled user: {} - {}", refused.statusCode(), refused.body().asString());
        assertThat(refused.statusCode()).isEqualTo(400);
        assertThat(refused.jsonPath().getString("error")).isEqualTo("invalid_grant");
        assertThat(refused.jsonPath().getString("error_description")).isEqualTo("Account disabled");
        assertThat(refused.jsonPath().getString("access_token")).isNull();

        // Re-enabled: disabling does not destroy PATs, they work again
        setUserEnabled(userId, true);
        assertThat(exchangePat(pat).statusCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("Should reject malformed PATs and unknown users before checking any PAT")
    void shouldRejectUnresolvableTokensUpFront() {
        // Store login events so we can see how each request was handled
        given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .contentType(ContentType.JSON)
                .body(Map.of("eventsEnabled", true))
                .when()
                .put("/admin/realms/" + REALM + "/events/config")
                .then().statusCode(204);
        int before = countUserNotFoundPatEvents();

        String unknownUserId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("no-such-user".getBytes(StandardCharsets.UTF_8));
        List<String> unresolvable = List.of(
                "pat_nouseridpart",                    // no separator
                "pat_!!not-base64!!.secret",           // user id part is not base64url
                "pat_" + unknownUserId + ".secret"     // well formed, but the user does not exist
        );
        for (String token : unresolvable) {
            Response response = exchangePat(token);
            assertThat(response.statusCode()).as(token).isEqualTo(400);
            assertThat(response.jsonPath().getString("error")).as(token).isEqualTo("invalid_grant");
        }

        // Each request was rejected up front as "user not found"
        assertThat(countUserNotFoundPatEvents() - before).isEqualTo(unresolvable.size());
    }

    @Test
    @DisplayName("Should keep a PAT imported with its realm working")
    void shouldKeepImportedPatWorking() {
        // realm-export.json imports user imported-pat-user with one PAT, stored as its SHA-256 hash the way
        // a realm export carries it. This is its token.
        String importedToken = "pat_NmExYzJiN2UtMGQ0Zi00YzNhLTliOGUtMWYyYTNiNGM1ZDZl.s79sV6L3RzJTiYFNc-EQh9v-rwqwqRfkDljnCIzQMT8";
        String userId = "6a1c2b7e-0d4f-4c3a-9b8e-1f2a3b4c5d6e";

        assertThat(getPatCredentialData(userId).get("name")).isEqualTo("Imported Token");

        // Wrong secret for this user: refused
        assertThat(exchangePat("pat_NmExYzJiN2UtMGQ0Zi00YzNhLTliOGUtMWYyYTNiNGM1ZDZl.wrong").statusCode()).isEqualTo(400);

        assertThat(exchangePat(importedToken).statusCode()).isEqualTo(200);
        assertThat(getPatCredentialData(userId).get("lastUsedAt")).isNotNull();
    }

    @Test
    @DisplayName("Should refuse to import a PAT that was not exported by Keycloak")
    void shouldRefuseImportOfHandWrittenPat() {
        String validHash = "{\"value\":\"o8LT2tQAQ8LWkPgVAIk0X8k9rLML2SSLoOzQyhJHwiQ\"}";
        String validMetadata = "{\"name\":\"Hand Written\",\"roles\":[]}";
        Map<String, Map<String, Object>> invalidPats = new LinkedHashMap<>();
        invalidPats.put("plain token value", Map.of("type", "pat", "userLabel", "Hand Written",
                "secretData", "{\"tokenValue\":\"pat_aGFuZC13cml0dGVu.c2VjcmV0\"}", "credentialData", validMetadata));
        invalidPats.put("no metadata", Map.of("type", "pat", "userLabel", "Hand Written", "secretData", validHash));
        invalidPats.put("no hash", Map.of("type", "pat", "userLabel", "Hand Written", "credentialData", validMetadata));

        invalidPats.forEach((invalidity, credential) -> {
            String username = "hand-written-" + invalidity.replace(' ', '-');
            Response response = given()
                    .header("Authorization", "Bearer " + getMasterAdminToken())
                    .contentType(ContentType.JSON)
                    .body(Map.of("ifResourceExists", "FAIL", "users", List.of(Map.of(
                            "username", username, "enabled", true, "credentials", List.of(credential)))))
                    .when()
                    .post("/admin/realms/" + REALM + "/partialImport");
            LOGGER.info("Partial import of a PAT with {}: {} - {}", invalidity, response.statusCode(), response.body().asString());
            assertThat(response.statusCode()).as(invalidity).isGreaterThanOrEqualTo(400);

            List<Object> users = given()
                    .header("Authorization", "Bearer " + getMasterAdminToken())
                    .queryParam("username", username)
                    .queryParam("exact", true)
                    .when().get("/admin/realms/" + REALM + "/users")
                    .then().statusCode(200).extract().jsonPath().getList("$");
            assertThat(users).as(invalidity).isEmpty();
        });
    }

    @Test
    @DisplayName("Should issue a standard access token: realm URL issuer, jti, azp, PAT roles only, no refresh or ID token")
    void shouldIssueStandardAccessToken() {
        String pat = createPatFor("christina", "Standard Token", List.of("test-role"));

        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "test-app")
                    .formParam("pat", pat)
                    .formParam("scope", "openid")
                    .when()
                    .post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.jsonPath().getString("refresh_token")).isNull();
            assertThat(response.jsonPath().getString("id_token")).isNull();

            String accessToken = response.jsonPath().getString("access_token");
            JsonPath claims = decodeClaims(accessToken);
            LOGGER.info("Standard PAT access token claims: {}", claims.prettify());
            assertThat(claims.getString("iss")).isEqualTo(getKeycloakBaseUrl() + "/realms/" + REALM);
            assertThat(claims.getString("jti")).isNotEmpty();
            assertThat(claims.getString("azp")).isEqualTo("test-app");
            assertThat(claims.getString("sub")).isEqualTo(getUserId("christina"));
            assertThat(claims.getString("scope")).doesNotContain("openid");
            assertThat(claims.getString("pat_name")).isEqualTo("Standard Token");
            // christina also holds the default roles and test-app:editor: only the PAT's role is kept
            assertThat(claims.getList("realm_access.roles", String.class)).containsExactly("test-role");
            assertThat(claims.getMap("resource_access")).isNull();
        } finally {
            deletePatsNamed("christina", "Standard Token");
        }
    }

    @Test
    @DisplayName("Should refuse PAT management with a token obtained with a PAT")
    void shouldRefusePatManagementWithTokenObtainedWithPat() {
        // A token from christina's PAT must not manage her PATs
        String patToken = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("client_id", "test-app")
                .formParam("pat", createPatFor("christina", "Chain Attempt Token", List.of()))
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token")
                .then().statusCode(200)
                .extract().jsonPath().getString("access_token");
        String existingPatId = given()
                .header("Authorization", "Bearer " + getRealmUserToken("christina", "admin"))
                .when()
                .get("/realms/" + REALM + "/pat")
                .then().statusCode(200)
                .extract().jsonPath().getString("[0].id");

        Map<String, Response> attempts = new LinkedHashMap<>();
        attempts.put("list", given().header("Authorization", "Bearer " + patToken).when().get("/realms/" + REALM + "/pat"));
        attempts.put("create for herself", given().header("Authorization", "Bearer " + patToken)
                .contentType(ContentType.JSON).body(Map.of("name", "Chained", "roles", List.of("test-role")))
                .when().post("/realms/" + REALM + "/pat"));
        attempts.put("rotate", given().header("Authorization", "Bearer " + patToken)
                .contentType(ContentType.JSON).body(Map.of())
                .when().post("/realms/" + REALM + "/pat/" + existingPatId + "/rotate"));
        attempts.put("delete", given().header("Authorization", "Bearer " + patToken).when().delete("/realms/" + REALM + "/pat/" + existingPatId));

        try {
            attempts.forEach((operation, response) ->
                    assertThat(response.statusCode()).as(operation).isEqualTo(403));
        } finally {
            deletePatsNamed("christina", "Chain Attempt Token");
        }
    }

    @Test
    @DisplayName("Should refuse to issue Admin API tokens from a PAT, so PATs never carry the user's admin rights")
    void shouldRefuseAdminApiTokensFromPat() {
        // A realm admin whose PAT has no roles at all
        String masterToken = getMasterAdminToken();
        given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "username", "pat-realm-admin", "enabled", true, "email", "pat-realm-admin@test.com",
                        "firstName", "Realm", "lastName", "Admin", "emailVerified", true,
                        "credentials", List.of(Map.of("type", "password", "value", "admin", "temporary", false))))
                .when()
                .post("/admin/realms/" + REALM + "/users")
                .then().statusCode(201);
        String userId = getUserId("pat-realm-admin");
        String realmManagementId = given()
                .header("Authorization", "Bearer " + masterToken)
                .queryParam("clientId", "realm-management")
                .when().get("/admin/realms/" + REALM + "/clients")
                .then().statusCode(200).extract().jsonPath().getString("[0].id");
        Map<String, Object> realmAdminRole = given()
                .header("Authorization", "Bearer " + masterToken)
                .when().get("/admin/realms/" + REALM + "/clients/" + realmManagementId + "/roles/realm-admin")
                .then().statusCode(200).extract().jsonPath().getMap("$");
        given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(List.of(realmAdminRole))
                .when().post("/admin/realms/" + REALM + "/users/" + userId + "/role-mappings/clients/" + realmManagementId)
                .then().statusCode(204);
        String pat = createPatFor("pat-realm-admin", "No Roles Token", List.of());
        // admin-cli accepts PATs here, so that the Admin API audience is what gets it refused
        setPatExchangeScope("admin-cli", true);
        try {
            // Through an Admin API client: refused
            Response viaAdminCli = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "admin-cli")
                    .formParam("pat", pat)
                    .when()
                    .post("/realms/" + REALM + "/protocol/openid-connect/token");
            LOGGER.info("PAT grant through admin-cli: {} - {}", viaAdminCli.statusCode(), viaAdminCli.body().asString());
            assertThat(viaAdminCli.statusCode()).isEqualTo(400);
            assertThat(viaAdminCli.jsonPath().getString("error")).isEqualTo("unauthorized_client");
            assertThat(viaAdminCli.jsonPath().getString("error_description")).contains("Admin API");

            // Through a regular client: issued, but the Admin API rejects it
            String regularToken = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "test-app")
                    .formParam("pat", pat)
                    .when()
                    .post("/realms/" + REALM + "/protocol/openid-connect/token")
                    .then().statusCode(200)
                    .extract().jsonPath().getString("access_token");
            assertThat(given().header("Authorization", "Bearer " + regularToken)
                    .when().get("/admin/realms/" + REALM + "/users").statusCode()).isEqualTo(401);
        } finally {
            setPatExchangeScope("admin-cli", false);
        }
    }

    @Test
    @DisplayName("Should refuse token exchange of a token obtained with a PAT, and keep it working for other tokens")
    void shouldRefuseTokenExchangeOfPatToken() {
        // Standard token exchange enabled and in its own audience: Keycloak would swap a PAT token issued to it for
        // a token with all of the user's roles
        createClient(Map.of(
                "clientId", "pat-exchanger", "enabled", true, "publicClient", false,
                "secret", "exchanger-secret", "standardFlowEnabled", false, "directAccessGrantsEnabled", true,
                "attributes", Map.of("standard.token.exchange.enabled", "true"),
                "protocolMappers", List.of(Map.of(
                        "name", "self-audience", "protocol", "openid-connect",
                        "protocolMapper", "oidc-audience-mapper",
                        "config", Map.of("included.client.audience", "pat-exchanger",
                                "access.token.claim", "true", "id.token.claim", "false")))));
        setPatExchangeScope("pat-exchanger", true);
        String pat = createPatFor("christina", "Token Exchange Attempt", List.of());
        try {
            String patToken = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "pat-exchanger")
                    .formParam("client_secret", "exchanger-secret")
                    .formParam("pat", pat)
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token")
                    .then().statusCode(200).extract().jsonPath().getString("access_token");

            Response refused = tokenExchange("pat-exchanger", "exchanger-secret", patToken);
            assertThat(refused.statusCode()).isEqualTo(400);
            assertThat(refused.jsonPath().getString("error_description")).contains("Personal Access Token");

            String userToken = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "password")
                    .formParam("client_id", "pat-exchanger")
                    .formParam("client_secret", "exchanger-secret")
                    .formParam("username", "christina")
                    .formParam("password", "admin")
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token")
                    .then().statusCode(200).extract().jsonPath().getString("access_token");
            assertThat(tokenExchange("pat-exchanger", "exchanger-secret", userToken).statusCode()).isEqualTo(200);
        } finally {
            deletePatsNamed("christina", "Token Exchange Attempt");
        }
    }

    @Test
    @DisplayName("Should refuse the UMA grant with a token obtained with a PAT, and keep it working for other tokens")
    void shouldRefuseUmaGrantWithPatToken() {
        createClient(Map.of(
                "clientId", "uma-resource-server", "enabled", true, "publicClient", false, "secret", "uma-secret",
                "standardFlowEnabled", false, "serviceAccountsEnabled", true, "authorizationServicesEnabled", true,
                "authorizationSettings", Map.of("policyEnforcementMode", "DISABLED",
                        "resources", List.of(Map.of("name", "resource")))));
        String pat = createPatFor("christina", "UMA Attempt", List.of());
        try {
            String patToken = exchangePat(pat).then().statusCode(200).extract().jsonPath().getString("access_token");

            Response bearer = umaGrant().header("Authorization", "Bearer " + patToken)
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(bearer.statusCode()).isEqualTo(400);
            assertThat(bearer.jsonPath().getString("error_description")).contains("Personal Access Token");

            // Keycloak reads the first Authorization header: a second one must not hide the PAT token
            for (String second : List.of("Bearer a.b", "Bearer a.b.c.d")) {
                Response twoHeaders = umaGrant()
                        .header("Authorization", "Bearer " + patToken)
                        .header("Authorization", second)
                        .when().post("/realms/" + REALM + "/protocol/openid-connect/token");
                assertThat(twoHeaders.statusCode()).as(second).isEqualTo(400);
                assertThat(twoHeaders.jsonPath().getString("error_description")).contains("Personal Access Token");
            }

            Response subjectToken = umaGrant()
                    .formParam("client_id", "uma-resource-server")
                    .formParam("client_secret", "uma-secret")
                    .formParam("subject_token", patToken)
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(subjectToken.statusCode()).isEqualTo(400);
            assertThat(subjectToken.jsonPath().getString("error_description")).contains("Personal Access Token");

            String userToken = getRealmUserToken("christina", "admin");
            Response allowed = umaGrant().header("Authorization", "Bearer " + userToken)
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(allowed.statusCode()).isEqualTo(200);
        } finally {
            deletePatsNamed("christina", "UMA Attempt");
        }
    }

    @Test
    @DisplayName("Should issue no ID token and refuse userinfo for a token obtained with a PAT")
    void shouldRefuseUserinfoForPatToken() {
        String pat = createPatFor("christina", "Userinfo Attempt", List.of("test-role"));
        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "test-app")
                    .formParam("pat", pat)
                    .formParam("scope", "openid microprofile-jwt")
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.jsonPath().getString("id_token")).isNull();
            String patToken = response.jsonPath().getString("access_token");
            JsonPath claims = decodeClaims(patToken);
            assertThat(claims.getString("scope")).doesNotContain("openid");
            assertThat(claims.getList("groups", String.class)).containsExactly("test-role");

            given().header("Authorization", "Bearer " + patToken)
                    .when().get("/realms/" + REALM + "/protocol/openid-connect/userinfo")
                    .then().statusCode(403);
        } finally {
            deletePatsNamed("christina", "Userinfo Attempt");
        }
    }

    @Test
    @DisplayName("Should refuse PAT management to service accounts")
    void shouldRefusePatManagementToServiceAccounts() {
        createClient(Map.of(
                "clientId", "pat-service", "enabled", true, "publicClient", false, "secret", "service-secret",
                "standardFlowEnabled", false, "serviceAccountsEnabled", true,
                "optionalClientScopes", List.of(PatConstants.PAT_MANAGEMENT_SCOPE)));
        String serviceToken = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .formParam("client_id", "pat-service")
                .formParam("client_secret", "service-secret")
                .formParam("scope", PatConstants.PAT_MANAGEMENT_SCOPE)
                .when().post("/realms/" + REALM + "/protocol/openid-connect/token")
                .then().statusCode(200).extract().jsonPath().getString("access_token");
        assertThat(decodeClaims(serviceToken).getString("scope")).contains(PatConstants.PAT_MANAGEMENT_SCOPE);

        given()
                .header("Authorization", "Bearer " + serviceToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Service Account Token"))
                .when().post("/realms/" + REALM + "/pat")
                .then().statusCode(403);
    }

    @Test
    @DisplayName("Should refuse PAT management in a session where an admin impersonates the user")
    void shouldRefusePatManagementWhenImpersonated() {
        String redirectUri = "http://localhost/callback";
        createClient(Map.of(
                "clientId", "pat-impersonation-app", "enabled", true, "publicClient", true,
                "standardFlowEnabled", true, "redirectUris", List.of(redirectUri),
                "optionalClientScopes", List.of(PatConstants.PAT_MANAGEMENT_SCOPE)));

        Map<String, String> sessionCookies = given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .when().post("/admin/realms/" + REALM + "/users/" + getUserId("christina") + "/impersonation")
                .then().statusCode(200).extract().cookies();

        String location = given()
                .cookies(sessionCookies)
                .redirects().follow(false)
                .queryParam("client_id", "pat-impersonation-app")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code")
                .queryParam("scope", PatConstants.PAT_MANAGEMENT_SCOPE)
                .when().get("/realms/" + REALM + "/protocol/openid-connect/auth")
                .then().statusCode(302).extract().header("Location");
        String code = location.replaceAll(".*[?&]code=([^&]+).*", "$1");

        String impersonatedToken = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("client_id", "pat-impersonation-app")
                .formParam("redirect_uri", redirectUri)
                .formParam("code", code)
                .when().post("/realms/" + REALM + "/protocol/openid-connect/token")
                .then().statusCode(200).extract().jsonPath().getString("access_token");
        assertThat(decodeClaims(impersonatedToken).getString("scope")).contains(PatConstants.PAT_MANAGEMENT_SCOPE);

        given()
                .header("Authorization", "Bearer " + impersonatedToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Impersonated Token"))
                .when().post("/realms/" + REALM + "/pat")
                .then().statusCode(403);
    }

    @Test
    @DisplayName("Should refuse the PAT grant while the user has pending required actions")
    void shouldRefusePatGrantWithPendingRequiredActions() {
        String userId = createTestUser("pat-required-action-user");
        try {
            String pat = createPatFor("pat-required-action-user", "Required Action Token", List.of());
            given()
                    .header("Authorization", "Bearer " + getMasterAdminToken())
                    .contentType(ContentType.JSON)
                    .body(Map.of("requiredActions", List.of("UPDATE_PASSWORD")))
                    .when().put("/admin/realms/" + REALM + "/users/" + userId)
                    .then().statusCode(204);

            Response response = exchangePat(pat);
            assertThat(response.statusCode()).isEqualTo(400);
            assertThat(response.jsonPath().getString("error_description")).isEqualTo("Account is not fully set up");
        } finally {
            deleteTestUser(userId);
        }
    }

    @Test
    @DisplayName("Should introspect a token obtained with a PAT with the PAT's roles only")
    void shouldIntrospectPatTokenWithPatRolesOnly() {
        createClient(Map.of(
                "clientId", "pat-resource-server", "enabled", true, "publicClient", false,
                "secret", "resource-server-secret", "standardFlowEnabled", false));
        createClient(Map.of(
                "clientId", "pat-introspected-app", "enabled", true, "publicClient", true,
                "standardFlowEnabled", false, "directAccessGrantsEnabled", true,
                "protocolMappers", List.of(Map.of(
                        "name", "resource-server-audience", "protocol", "openid-connect",
                        "protocolMapper", "oidc-audience-mapper",
                        "config", Map.of("included.client.audience", "pat-resource-server",
                                "access.token.claim", "true", "introspection.token.claim", "true")))));
        setPatExchangeScope("pat-introspected-app", true);
        String pat = createPatFor("christina", "Introspection Token", List.of("test-role"));
        try {
            String patToken = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "pat-introspected-app")
                    .formParam("pat", pat)
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token")
                    .then().statusCode(200).extract().jsonPath().getString("access_token");

            JsonPath introspection = introspect(patToken);
            assertThat(introspection.getBoolean("active")).isTrue();
            assertThat(introspection.getList("realm_access.roles", String.class)).containsExactly("test-role");
            assertThat(introspection.getMap("resource_access")).isNull();
            assertThat(introspection.getString("pat_name")).isEqualTo("Introspection Token");

            // Other tokens are still introspected by Keycloak itself, with the user's roles
            String userToken = getRealmUserToken("pat-introspected-app", "christina", "admin", null);
            JsonPath userIntrospection = introspect(userToken);
            assertThat(userIntrospection.getBoolean("active")).isTrue();
            assertThat(userIntrospection.getList("realm_access.roles", String.class)).contains("test-role", "offline_access");
        } finally {
            deletePatsNamed("christina", "Introspection Token");
        }
    }

    @Test
    @DisplayName("Should refuse the Account API to a token obtained with a PAT")
    void shouldRefuseAccountApiForPatToken() {
        String pat = createPatFor("christina", "Account API Attempt", List.of("test-role"));
        try {
            String patToken = exchangePat(pat).then().statusCode(200).extract().jsonPath().getString("access_token");

            Response profile = given()
                    .header("Authorization", "Bearer " + patToken)
                    .accept(ContentType.JSON)
                    .when().get("/realms/" + REALM + "/account");
            assertThat(profile.statusCode()).isIn(401, 403);

            Response credentials = given()
                    .header("Authorization", "Bearer " + patToken)
                    .accept(ContentType.JSON)
                    .when().get("/realms/" + REALM + "/account/credentials");
            assertThat(credentials.statusCode()).isIn(401, 403);
        } finally {
            deletePatsNamed("christina", "Account API Attempt");
        }
    }

    @Test
    @DisplayName("Should refuse the PAT grant to a client issuing lightweight access tokens")
    void shouldRefusePatGrantForLightweightTokenClient() {
        createClient(Map.of(
                "clientId", "pat-lightweight-app", "enabled", true, "publicClient", true,
                "standardFlowEnabled", false,
                "attributes", Map.of("client.use.lightweight.access.token.enabled", "true")));
        setPatExchangeScope("pat-lightweight-app", true);
        String pat = createPatFor("christina", "Lightweight Attempt", List.of("test-role"));
        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "pat-lightweight-app")
                    .formParam("pat", pat)
                    .when().post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(response.statusCode()).isEqualTo(400);
            assertThat(response.jsonPath().getString("error")).isEqualTo("unauthorized_client");
            assertThat(response.jsonPath().getString("error_description")).contains("lightweight");
        } finally {
            deletePatsNamed("christina", "Lightweight Attempt");
        }
    }

    @Test
    @DisplayName("Should give a PAT without roles an empty realm_access, so Keycloak never takes it for a lightweight token")
    void shouldMarkRolelessPatTokenWithEmptyRealmAccess() {
        String pat = createPatFor("christina", "Roleless Token", List.of());
        try {
            String patToken = exchangePat(pat).then().statusCode(200).extract().jsonPath().getString("access_token");
            JsonPath claims = decodeClaims(patToken);
            assertThat(claims.getMap("realm_access")).isNotNull();
            assertThat(claims.getList("realm_access.roles", String.class)).isEmpty();
            assertThat(claims.getString("sid")).isNull();
        } finally {
            deletePatsNamed("christina", "Roleless Token");
        }
    }

    @Test
    @DisplayName("Should accept role names and client ids containing ':'")
    void shouldAcceptRolesContainingColons() {
        String masterToken = getMasterAdminToken();
        String christinaId = getUserId("christina");
        given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                .body(Map.of("name", "app:read"))
                .when().post("/admin/realms/" + REALM + "/roles").then().statusCode(201);
        Map<String, Object> realmRole = given().header("Authorization", "Bearer " + masterToken)
                .when().get("/admin/realms/" + REALM + "/roles/app:read")
                .then().statusCode(200).extract().jsonPath().getMap("$");
        given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                .body(List.of(realmRole))
                .when().post("/admin/realms/" + REALM + "/users/" + christinaId + "/role-mappings/realm")
                .then().statusCode(204);

        createClient(Map.of("clientId", "urn:test:app", "enabled", true, "publicClient", true));
        String clientUuid = given().header("Authorization", "Bearer " + masterToken).queryParam("clientId", "urn:test:app")
                .when().get("/admin/realms/" + REALM + "/clients")
                .then().statusCode(200).extract().jsonPath().getString("[0].id");
        given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                .body(Map.of("name", "viewer"))
                .when().post("/admin/realms/" + REALM + "/clients/" + clientUuid + "/roles").then().statusCode(201);
        Map<String, Object> clientRole = given().header("Authorization", "Bearer " + masterToken)
                .when().get("/admin/realms/" + REALM + "/clients/" + clientUuid + "/roles/viewer")
                .then().statusCode(200).extract().jsonPath().getMap("$");
        given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                .body(List.of(clientRole))
                .when().post("/admin/realms/" + REALM + "/users/" + christinaId + "/role-mappings/clients/" + clientUuid)
                .then().statusCode(204);

        Response response = given()
                .header("Authorization", "Bearer " + getRealmUserToken("christina", "admin"))
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Colon Roles Token", "roles", List.of("app:read", "urn:test:app:viewer")))
                .when().post("/realms/" + REALM + "/pat");
        try {
            assertThat(response.statusCode()).isEqualTo(201);
            assertThat(response.jsonPath().getList("roles")).containsExactly("app:read", "urn:test:app:viewer");
        } finally {
            deletePatsNamed("christina", "Colon Roles Token");
        }
    }

    @Test
    @DisplayName("Should refuse an ambiguous role name, and drop it from existing PATs")
    void shouldRefuseAmbiguousRoleNames() {
        String masterToken = getMasterAdminToken();
        String christinaId = getUserId("christina");
        createClient(Map.of("clientId", "pat-ambiguous-app", "enabled", true, "publicClient", true));
        String clientUuid = given().header("Authorization", "Bearer " + masterToken).queryParam("clientId", "pat-ambiguous-app")
                .when().get("/admin/realms/" + REALM + "/clients")
                .then().statusCode(200).extract().jsonPath().getString("[0].id");
        given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                .body(Map.of("name", "read"))
                .when().post("/admin/realms/" + REALM + "/clients/" + clientUuid + "/roles").then().statusCode(201);
        Map<String, Object> clientRole = given().header("Authorization", "Bearer " + masterToken)
                .when().get("/admin/realms/" + REALM + "/clients/" + clientUuid + "/roles/read")
                .then().statusCode(200).extract().jsonPath().getMap("$");
        given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                .body(List.of(clientRole))
                .when().post("/admin/realms/" + REALM + "/users/" + christinaId + "/role-mappings/clients/" + clientUuid)
                .then().statusCode(204);

        String pat = createPatFor("christina", "Ambiguous Token", List.of("pat-ambiguous-app:read"));
        try {
            // A realm role named like the spec appears afterwards, and the user gets it
            given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                    .body(Map.of("name", "pat-ambiguous-app:read"))
                    .when().post("/admin/realms/" + REALM + "/roles").then().statusCode(201);
            Map<String, Object> realmRole = given().header("Authorization", "Bearer " + masterToken)
                    .when().get("/admin/realms/" + REALM + "/roles/pat-ambiguous-app:read")
                    .then().statusCode(200).extract().jsonPath().getMap("$");
            given().header("Authorization", "Bearer " + masterToken).contentType(ContentType.JSON)
                    .body(List.of(realmRole))
                    .when().post("/admin/realms/" + REALM + "/users/" + christinaId + "/role-mappings/realm")
                    .then().statusCode(204);

            Response creation = given()
                    .header("Authorization", "Bearer " + getRealmUserToken("christina", "admin"))
                    .contentType(ContentType.JSON)
                    .body(Map.of("name", "Ambiguous Token 2", "roles", List.of("pat-ambiguous-app:read")))
                    .when().post("/realms/" + REALM + "/pat");
            assertThat(creation.statusCode()).isEqualTo(400);
            assertThat(creation.jsonPath().getString("error")).contains("Ambiguous role");

            String patToken = exchangePat(pat).then().statusCode(200).extract().jsonPath().getString("access_token");
            JsonPath claims = decodeClaims(patToken);
            assertThat(claims.getList("realm_access.roles", String.class)).doesNotContain("pat-ambiguous-app:read");
            assertThat(claims.getMap("resource_access")).isNull();
            assertThat(claims.getList("pat_roles", String.class)).isEmpty();
        } finally {
            deletePatsNamed("christina", "Ambiguous Token");
        }
    }

    @Test
    @DisplayName("Should add CORS headers to PAT grant errors")
    void shouldAddCorsHeadersToPatGrantErrors() {
        String origin = "http://localhost:3000";
        createClient(Map.of(
                "clientId", "pat-browser-app", "enabled", true, "publicClient", true,
                "standardFlowEnabled", false, "webOrigins", List.of(origin)));
        setPatExchangeScope("pat-browser-app", true);

        Response response = given()
                .header("Origin", origin)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("client_id", "pat-browser-app")
                .formParam("pat", "pat_" + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(getUserId("christina").getBytes(StandardCharsets.UTF_8)) + ".invalid")
                .when().post("/realms/" + REALM + "/protocol/openid-connect/token");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.jsonPath().getString("error")).isEqualTo("invalid_grant");
        assertThat(response.header("Access-Control-Allow-Origin")).isEqualTo(origin);
    }

    @Test
    @DisplayName("Should keep the roles contained in a composite role of the PAT")
    void shouldKeepRolesOfCompositePatRole() {
        String masterToken = getMasterAdminToken();
        given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "pat-bundle", "composite", true))
                .when().post("/admin/realms/" + REALM + "/roles")
                .then().statusCode(201);
        Map<String, Object> testRole = given()
                .header("Authorization", "Bearer " + masterToken)
                .when().get("/admin/realms/" + REALM + "/roles/test-role")
                .then().statusCode(200).extract().jsonPath().getMap("$");
        given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(List.of(testRole))
                .when().post("/admin/realms/" + REALM + "/roles/pat-bundle/composites")
                .then().statusCode(204);
        given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "username", "pat-composite-user", "enabled", true, "email", "pat-composite-user@test.com",
                        "firstName", "Composite", "lastName", "User", "emailVerified", true,
                        "credentials", List.of(Map.of("type", "password", "value", "admin", "temporary", false))))
                .when().post("/admin/realms/" + REALM + "/users")
                .then().statusCode(201);
        Map<String, Object> bundleRole = given()
                .header("Authorization", "Bearer " + masterToken)
                .when().get("/admin/realms/" + REALM + "/roles/pat-bundle")
                .then().statusCode(200).extract().jsonPath().getMap("$");
        given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(List.of(bundleRole))
                .when().post("/admin/realms/" + REALM + "/users/" + getUserId("pat-composite-user") + "/role-mappings/realm")
                .then().statusCode(204);

        Response response = exchangePat(createPatFor("pat-composite-user", "Composite Token", List.of("pat-bundle")));
        assertThat(response.statusCode()).isEqualTo(200);
        JsonPath claims = decodeClaims(response.jsonPath().getString("access_token"));
        // The composite and the role it contains, but none of the user's other roles (default roles)
        assertThat(claims.getList("realm_access.roles", String.class)).containsExactlyInAnyOrder("pat-bundle", "test-role");
    }

    @Test
    @DisplayName("Should accept PATs only on clients with the pat-exchange scope, which the extension assigns to none")
    void shouldAcceptPatsOnlyOnOptedInClients() {
        String pat = createPatFor("christina", "Opt In Token", List.of());
        try {
            // admin-cli does not have the scope: refused before the PAT is even looked at
            Response refused = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "admin-cli")
                    .formParam("pat", pat)
                    .when()
                    .post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(refused.statusCode()).isEqualTo(400);
            assertThat(refused.jsonPath().getString("error")).isEqualTo("unauthorized_client");
            assertThat(refused.jsonPath().getString("error_description")).contains(PatConstants.PAT_EXCHANGE_SCOPE);

            // test-app has it (as a default scope, in realm-export.json): accepted
            assertThat(exchangePat(pat).statusCode()).isEqualTo(200);
        } finally {
            deletePatsNamed("christina", "Opt In Token");
        }

        // A realm created while Keycloak runs gets both scopes, and no client has pat-exchange
        String masterToken = getMasterAdminToken();
        given()
                .header("Authorization", "Bearer " + masterToken)
                .contentType(ContentType.JSON)
                .body(Map.of("realm", "pat-new-realm", "enabled", true))
                .when().post("/admin/realms")
                .then().statusCode(201);
        try {
            List<String> scopeNames = given()
                    .header("Authorization", "Bearer " + masterToken)
                    .when().get("/admin/realms/pat-new-realm/client-scopes")
                    .then().statusCode(200).extract().jsonPath().getList("name");
            assertThat(scopeNames).contains(PatConstants.PAT_EXCHANGE_SCOPE, PatConstants.PAT_MANAGEMENT_SCOPE);

            List<Map<String, Object>> clients = given()
                    .header("Authorization", "Bearer " + masterToken)
                    .when().get("/admin/realms/pat-new-realm/clients")
                    .then().statusCode(200).extract().jsonPath().getList("$");
            assertThat(clients).allSatisfy(c -> {
                assertThat((List<Object>) c.getOrDefault("defaultClientScopes", List.of())).doesNotContain(PatConstants.PAT_EXCHANGE_SCOPE);
                assertThat((List<Object>) c.getOrDefault("optionalClientScopes", List.of())).doesNotContain(PatConstants.PAT_EXCHANGE_SCOPE);
            });
            // admin-cli exists when the realm-created event fires, so it got pat-management as an optional scope
            Map<String, Object> adminCli = clients.stream()
                    .filter(c -> "admin-cli".equals(c.get("clientId")))
                    .findFirst().orElseThrow();
            assertThat((List<Object>) adminCli.get("optionalClientScopes")).contains(PatConstants.PAT_MANAGEMENT_SCOPE);
        } finally {
            given().header("Authorization", "Bearer " + masterToken)
                    .when().delete("/admin/realms/pat-new-realm")
                    .then().statusCode(204);
        }
    }

    @Test
    @DisplayName("Should refuse PAT management to a user disabled after getting a pat-management token")
    void shouldRefusePatManagementToDisabledUser() {
        String userId = createTestUser("pat-disabled-user");
        try {
            String token = getRealmUserToken("pat-disabled-user", "admin");
            String patId = given()
                    .header("Authorization", "Bearer " + token)
                    .contentType(ContentType.JSON)
                    .body(Map.of("name", "Before Disable", "expirationDays", 30))
                    .when().post("/realms/" + REALM + "/pat")
                    .then().statusCode(201).extract().jsonPath().getString("id");

            setUserEnabled(userId, false);

            // The token is not expired, but Keycloak's bearer authentication refuses disabled users
            given()
                    .header("Authorization", "Bearer " + token)
                    .contentType(ContentType.JSON)
                    .body(Map.of("name", "After Disable", "expirationDays", 30))
                    .when().post("/realms/" + REALM + "/pat")
                    .then().statusCode(401);
            given()
                    .header("Authorization", "Bearer " + token)
                    .when().post("/realms/" + REALM + "/pat/" + patId + "/rotate")
                    .then().statusCode(401);
        } finally {
            deleteTestUser(userId);
        }
    }

    /** Assigns (as optional) or removes the pat-exchange client scope on a client of the test realm. */
    private void setPatExchangeScope(String clientId, boolean assigned) {
        String masterToken = getMasterAdminToken();
        String clientUuid = given()
                .header("Authorization", "Bearer " + masterToken)
                .queryParam("clientId", clientId)
                .when().get("/admin/realms/" + REALM + "/clients")
                .then().statusCode(200).extract().jsonPath().getString("[0].id");
        String scopeId = given()
                .header("Authorization", "Bearer " + masterToken)
                .when().get("/admin/realms/" + REALM + "/client-scopes")
                .then().statusCode(200).extract().jsonPath()
                .getString("find { it.name == '" + PatConstants.PAT_EXCHANGE_SCOPE + "' }.id");
        String path = "/admin/realms/" + REALM + "/clients/" + clientUuid + "/optional-client-scopes/" + scopeId;
        if (assigned) {
            given().header("Authorization", "Bearer " + masterToken).when().put(path).then().statusCode(204);
        } else {
            given().header("Authorization", "Bearer " + masterToken).when().delete(path).then().statusCode(204);
        }
    }

    /** Creates a PAT for a user (logging in as that user, password "admin") and returns its token value. */
    private String createPatFor(String username, String name, List<String> roles) {
        return given()
                .header("Authorization", "Bearer " + getRealmUserToken(username, "admin"))
                .contentType(ContentType.JSON)
                .body(Map.of("name", name, "expirationDays", 30, "roles", roles))
                .when()
                .post("/realms/" + REALM + "/pat")
                .then().statusCode(201)
                .extract().jsonPath().getString("token");
    }

    /** Deletes a user's PATs by name, so tests stay under the per-user PAT limit. */
    private void deletePatsNamed(String username, String... names) {
        String token = getRealmUserToken(username, "admin");
        String userId = getUserId(username);
        List<Map<String, Object>> pats = given()
                .header("Authorization", "Bearer " + token)
                .when().get("/realms/" + REALM + "/pat")
                .then().statusCode(200)
                .extract().jsonPath().getList("$");
        pats.stream()
                .filter(p -> List.of(names).contains(p.get("name")))
                .forEach(p -> given()
                        .header("Authorization", "Bearer " + token)
                        .when().delete("/realms/" + REALM + "/pat/" + p.get("id"))
                        .then().statusCode(204));
    }

    private static JsonPath decodeClaims(String jwt) {
        return JsonPath.from(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8));
    }

    /** credentialData of the user's only PAT, as stored (read through the admin API). */
    private Map<String, Object> getPatCredentialData(String userId) {
        List<Map<String, Object>> pats = getPatCredentials(userId);
        assertThat(pats).hasSize(1);
        return parseJson((String) pats.get(0).get("credentialData"));
    }

    private List<Map<String, Object>> getPatCredentials(String userId) {
        List<Map<String, Object>> credentials = given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .when()
                .get("/admin/realms/" + REALM + "/users/" + userId + "/credentials")
                .then().statusCode(200)
                .extract().jsonPath().getList("$");
        return credentials.stream().filter(c -> PatConstants.CREDENTIAL_TYPE.equals(c.get("type"))).toList();
    }

    private static Map<String, Object> parseJson(String json) {
        return JsonPath.from(json).getMap("$");
    }

    private int countUserNotFoundPatEvents() {
        List<Map<String, Object>> events = given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .queryParam("type", "LOGIN_ERROR")
                .queryParam("max", 1000)
                .when()
                .get("/admin/realms/" + REALM + "/events")
                .then().statusCode(200)
                .extract().jsonPath().getList("$");
        return (int) events.stream()
                .filter(e -> "user_not_found".equals(e.get("error")))
                .filter(e -> e.get("details") instanceof Map<?, ?> d && "pat".equals(d.get("auth_method")))
                .count();
    }

    private Response tokenExchange(String clientId, String clientSecret, String subjectToken) {
        return given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .formParam("client_id", clientId)
                .formParam("client_secret", clientSecret)
                .formParam("subject_token", subjectToken)
                .formParam("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");
    }

    private JsonPath introspect(String token) {
        return given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .formParam("client_id", "pat-resource-server")
                .formParam("client_secret", "resource-server-secret")
                .when().post("/realms/" + REALM + "/protocol/openid-connect/token/introspect")
                .then().statusCode(200).extract().jsonPath();
    }

    private RequestSpecification umaGrant() {
        return given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
                .formParam("audience", "uma-resource-server");
    }

    private void createClient(Map<String, Object> representation) {
        given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .contentType(ContentType.JSON)
                .body(representation)
                .when()
                .post("/admin/realms/" + REALM + "/clients")
                .then().statusCode(201);
    }

    private Response exchangePat(String pat) {
        return given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("client_id", "test-app")
                .formParam("pat", pat)
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");
    }

    private void setUserEnabled(String userId, boolean enabled) {
        given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .contentType(ContentType.JSON)
                .body(Map.of("enabled", enabled))
                .when()
                .put("/admin/realms/" + REALM + "/users/" + userId)
                .then().statusCode(204);
    }

    @Test
    @DisplayName("Should not lock the user out after repeated invalid PATs")
    void shouldNotLockOutUserAfterInvalidPats() {
        String userId = createTestUser("pat-not-locked-user");
        try {
            String validToken = createPatFor("pat-not-locked-user", "Lockout Test Token", List.of());
            // Same user id, wrong random part
            String invalidToken = validToken.substring(0, validToken.indexOf('.') + 1) + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

            // More than the realm's failureFactor of 5
            for (int i = 0; i < 6; i++) {
                Response response = exchangePat(invalidToken);
                assertThat(response.jsonPath().getString("error_description"))
                    .isEqualTo("Invalid or expired Personal Access Token");
            }

            assertThat(exchangePat(validToken).statusCode()).isEqualTo(200);
            getRealmUserToken("pat-not-locked-user", "admin");
        } finally {
            deleteTestUser(userId);
        }
    }

    // ========== List PATs Tests ==========

    @Test
    @DisplayName("Should list all PATs for a user")
    void shouldListAllPatsForUser() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .when()
                .get("/realms/" + REALM + "/pat");

        LOGGER.info("List PATs response: {} - {}", response.statusCode(), response.body().asString());

        assertThat(response.statusCode()).isEqualTo(200);
        List<Map<String, Object>> pats = response.jsonPath().getList("$");
        assertThat(pats).isNotEmpty();

        // Verify each item has expected fields and NO token value
        Map<String, Object> firstPat = pats.get(0);
        assertThat(firstPat).containsKey("id");
        assertThat(firstPat).containsKey("name");
        assertThat(firstPat).containsKey("roles");
        assertThat(firstPat).containsKey("createdAt");
        assertThat(firstPat).containsKey("active");
        assertThat(firstPat).doesNotContainKey("token");
    }

    @Test
    @DisplayName("Should list and get only the caller's own PATs")
    void shouldListAndGetOnlyOwnPats() {
        String christinaToken = getRealmUserToken("christina", "admin");
        Response createResponse = given()
                .header("Authorization", "Bearer " + christinaToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Christina Private Token"))
                .when()
                .post("/realms/" + REALM + "/pat");
        assertThat(createResponse.statusCode()).isEqualTo(201);
        String credentialId = createResponse.jsonPath().getString("id");

        try {
            String hannaToken = getRealmUserToken("hanna", "admin");
            List<String> hannaPats = given()
                    .header("Authorization", "Bearer " + hannaToken)
                    .when()
                    .get("/realms/" + REALM + "/pat")
                    .then().statusCode(200)
                    .extract().jsonPath().getList("id");
            assertThat(hannaPats).doesNotContain(credentialId);

            assertThat(given()
                    .header("Authorization", "Bearer " + hannaToken)
                    .when()
                    .get("/realms/" + REALM + "/pat/" + credentialId)
                    .statusCode()).isEqualTo(404);
        } finally {
            deletePatsNamed("christina", "Christina Private Token");
        }
    }

    // ========== Get PAT Tests ==========

    @Test
    @DisplayName("Should get a single PAT by ID")
    void shouldGetSinglePatById() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create a PAT
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Get Test Token",
                        "expirationDays", 60,
                        "roles", List.of("test-role")
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String credentialId = createResponse.jsonPath().getString("id");

        // Get the PAT by ID
        Response getResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .when()
                .get("/realms/" + REALM + "/pat/" + credentialId);

        LOGGER.info("Get PAT response: {} - {}", getResponse.statusCode(), getResponse.body().asString());

        assertThat(getResponse.statusCode()).isEqualTo(200);
        assertThat(getResponse.jsonPath().getString("id")).isEqualTo(credentialId);
        assertThat(getResponse.jsonPath().getString("name")).isEqualTo("Get Test Token");
        assertThat(getResponse.jsonPath().getList("roles")).containsExactly("test-role");
        assertThat(getResponse.jsonPath().getString("createdAt")).isNotNull();
        assertThat(getResponse.jsonPath().getString("expiresAt")).isNotNull();
        assertThat(getResponse.jsonPath().getBoolean("active")).isTrue();
        // Must never expose token value
        assertThat(getResponse.body().asString()).doesNotContain("pat_");
    }

    @Test
    @DisplayName("Should return 404 for non-existent PAT ID")
    void shouldReturn404ForNonExistentPatId() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .when()
                .get("/realms/" + REALM + "/pat/non-existent-id");

        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.jsonPath().getString("error")).contains("PAT not found");
    }

    // ========== Delete PAT Tests ==========

    @Test
    @DisplayName("Should delete a PAT")
    void shouldDeletePat() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create a PAT
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Delete Test Token",
                        "expirationDays", 30
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String credentialId = createResponse.jsonPath().getString("id");

        // Delete the PAT
        Response deleteResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .when()
                .delete("/realms/" + REALM + "/pat/" + credentialId);

        LOGGER.info("Delete PAT response: {}", deleteResponse.statusCode());

        assertThat(deleteResponse.statusCode()).isEqualTo(204);

        // Verify it's gone - GET should return 404
        Response getResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .when()
                .get("/realms/" + REALM + "/pat/" + credentialId);

        assertThat(getResponse.statusCode()).isEqualTo(404);
    }

    @Test
    @DisplayName("Should reject authentication with deleted PAT via grant type")
    void shouldRejectAuthenticationWithDeletedPat() {
        String realmToken = getRealmUserToken("christina", "admin");

        // Create a PAT
        Response createResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Delete Auth Test Token"
                ))
                .when()
                .post("/realms/" + REALM + "/pat");

        assertThat(createResponse.statusCode()).isEqualTo(201);
        String patToken = createResponse.jsonPath().getString("token");
        String credentialId = createResponse.jsonPath().getString("id");

        // Verify PAT works before deletion
        Response tokenResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", patToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode()).isEqualTo(200);

        // Delete the PAT
        Response deleteResponse = given()
                .header("Authorization", "Bearer " + realmToken)
                .when()
                .delete("/realms/" + REALM + "/pat/" + credentialId);

        assertThat(deleteResponse.statusCode()).isEqualTo(204);

        // Try to authenticate with the deleted PAT - should fail
        Response rejectedResponse = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", GRANT_TYPE)
                .formParam("pat", patToken)
                .formParam("client_id", "test-app")
                .when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        LOGGER.info("Deleted PAT auth response: {} - {}", rejectedResponse.statusCode(), rejectedResponse.body().asString());

        assertThat(rejectedResponse.statusCode()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should return 404 when deleting non-existent PAT")
    void shouldReturn404WhenDeletingNonExistentPat() {
        String realmToken = getRealmUserToken("christina", "admin");

        Response response = given()
                .header("Authorization", "Bearer " + realmToken)
                .when()
                .delete("/realms/" + REALM + "/pat/non-existent-id");

        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.jsonPath().getString("error")).contains("PAT not found");
    }

    @Test
    @DisplayName("Should not let a user delete another user's PAT")
    void shouldNotDeleteAnotherUsersPat() {
        String christinaToken = getRealmUserToken("christina", "admin");

        Response createResponse = given()
                .header("Authorization", "Bearer " + christinaToken)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "Delete Auth Block Token"))
                .when()
                .post("/realms/" + REALM + "/pat");
        assertThat(createResponse.statusCode()).isEqualTo(201);
        String credentialId = createResponse.jsonPath().getString("id");
        String token = createResponse.jsonPath().getString("token");

        // hanna names christina's PAT: it is not one of hers, so it does not exist for her
        Response deleteResponse = given()
                .header("Authorization", "Bearer " + getRealmUserToken("hanna", "admin"))
                .when()
                .delete("/realms/" + REALM + "/pat/" + credentialId);

        assertThat(deleteResponse.statusCode()).isEqualTo(404);
        assertThat(exchangePat(token).statusCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("Should narrow every role-derived claim to the PAT's roles, including the microprofile-jwt groups claim")
    void shouldNarrowRoleClaimsFromAnyScopeToPatRoles() {
        // christina also holds test-app:editor and the default roles: none of them may leak
        String pat = createPatFor("christina", "pat-groups-claim", List.of("test-role"));
        try {
            Response response = given()
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", GRANT_TYPE)
                    .formParam("client_id", "test-app")
                    .formParam("scope", "microprofile-jwt")
                    .formParam("pat", pat)
                    .when()
                    .post("/realms/" + REALM + "/protocol/openid-connect/token");
            assertThat(response.statusCode()).isEqualTo(200);

            JsonPath claims = decodeClaims(response.jsonPath().getString("access_token"));
            assertThat(claims.getString("scope")).contains("microprofile-jwt");
            assertThat(claims.getList("groups", String.class)).containsExactly("test-role");
            assertThat(claims.getList("realm_access.roles", String.class)).containsExactly("test-role");
            assertThat(claims.getMap("resource_access")).isNull();
        } finally {
            deletePatsNamed("christina", "pat-groups-claim");
        }
    }

    @Test
    @DisplayName("Should record a successful PAT exchange as a LOGIN event carrying the PAT id and name")
    void shouldRecordSuccessfulPatExchangeAsLoginEvent() {
        String pat = createPatFor("christina", "pat-login-event", List.of("test-role"));
        try {
            exchangePat(pat).then().statusCode(200);

            List<Map<String, Object>> events = given()
                    .header("Authorization", "Bearer " + getMasterAdminToken())
                    .queryParam("type", "LOGIN")
                    .queryParam("client", "test-app")
                    .queryParam("max", 1000)
                    .when()
                    .get("/admin/realms/" + REALM + "/events")
                    .then().statusCode(200)
                    .extract().jsonPath().getList("$");
            assertThat(events)
                    .filteredOn(e -> e.get("details") instanceof Map<?, ?> d
                            && "pat".equals(d.get("auth_method"))
                            && "pat-login-event".equals(d.get(PatConstants.CLAIM_PAT_NAME))
                            && d.get(PatConstants.CLAIM_PAT_ID) != null)
                    .hasSize(1)
                    .first()
                    .satisfies(e -> assertThat(e.get("userId")).isEqualTo(getUserId("christina")));
        } finally {
            deletePatsNamed("christina", "pat-login-event");
        }
    }

    @Test
    @DisplayName("Should require the pat-management scope to manage PATs, offered only to admin-cli by default")
    void shouldRequirePatManagementScope() {
        String patApi = "/realms/" + REALM + "/pat";

        // The extension created the scope and made it an optional scope of admin-cli
        String masterToken = getMasterAdminToken();
        List<String> scopeNames = given()
                .header("Authorization", "Bearer " + masterToken)
                .get("/admin/realms/" + REALM + "/client-scopes")
                .jsonPath().getList("name");
        assertThat(scopeNames).contains(PatConstants.PAT_MANAGEMENT_SCOPE);

        // admin-cli with the scope: allowed
        String withScope = getRealmUserToken("admin-cli", "christina", "admin", PatConstants.PAT_MANAGEMENT_SCOPE);
        assertThat(decodeClaims(withScope).getString("scope")).contains(PatConstants.PAT_MANAGEMENT_SCOPE);
        given().header("Authorization", "Bearer " + withScope).get(patApi).then().statusCode(200);

        // admin-cli without requesting the optional scope: refused
        String withoutScope = getRealmUserToken("admin-cli", "christina", "admin", null);
        Response refused = given().header("Authorization", "Bearer " + withoutScope).get(patApi);
        assertThat(refused.statusCode()).isEqualTo(403);
        assertThat(refused.asString()).contains(PatConstants.PAT_MANAGEMENT_SCOPE);

        // Any other client of the realm (scope not assigned to it): refused, for listing and for creating
        String otherClient = getRealmUserToken("test-app", "christina", "admin", null);
        given().header("Authorization", "Bearer " + otherClient).get(patApi).then().statusCode(403);
        given().header("Authorization", "Bearer " + otherClient)
                .contentType(ContentType.JSON)
                .body(Map.of("name", "from-other-client", "expirationDays", 30))
                .post(patApi)
                .then().statusCode(403);

        // ...and it cannot even obtain the scope
        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("client_id", "test-app")
                .formParam("username", "christina")
                .formParam("password", "admin")
                .formParam("scope", PatConstants.PAT_MANAGEMENT_SCOPE)
                .post("/realms/" + REALM + "/protocol/openid-connect/token")
                .then().statusCode(400);
    }

    @Test
    @DisplayName("Should let an admin see and revoke one PAT of a user with Keycloak's Admin API")
    void shouldLetAdminRevokeOnePatWithAdminApi() {
        // A user of its own: other tests leave PATs behind and the limit is 25 per user
        String userId = createTestUser("pat-revoked-user");
        String revoked = createPatFor("pat-revoked-user", "Admin Revoked Token", List.of());
        String kept = createPatFor("pat-revoked-user", "Admin Kept Token", List.of());

        String credentialId = getPatCredentials(userId).stream()
                .filter(c -> "Admin Revoked Token".equals(c.get("userLabel")))
                .findFirst().orElseThrow()
                .get("id").toString();

        given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .when()
                .delete("/admin/realms/" + REALM + "/users/" + userId + "/credentials/" + credentialId)
                .then().statusCode(204);

        assertThat(exchangePat(revoked).statusCode()).isEqualTo(400);
        assertThat(exchangePat(kept).statusCode()).isEqualTo(200);
    }

    // ========== Helper Methods ==========

    /** Creates an enabled user of the test realm with password "admin" and returns its id. */
    private String createTestUser(String username) {
        given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "username", username, "enabled", true, "email", username + "@test.com",
                        "firstName", "Test", "lastName", "User", "emailVerified", true,
                        "credentials", List.of(Map.of("type", "password", "value", "admin", "temporary", false))))
                .when()
                .post("/admin/realms/" + REALM + "/users")
                .then().statusCode(201);
        return getUserId(username);
    }

    private void deleteTestUser(String userId) {
        given()
                .header("Authorization", "Bearer " + getMasterAdminToken())
                .when().delete("/admin/realms/" + REALM + "/users/" + userId)
                .then().statusCode(204);
    }

    /**
     * Gets an admin access token from the master realm using admin-cli.
     * Used for Keycloak Admin API calls (e.g., listing users).
     */
    private String getMasterAdminToken() {
        Response response = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("client_id", "admin-cli")
                .formParam("username", "admin")
                .formParam("password", "admin")
                .when()
                .post("/realms/master/protocol/openid-connect/token");

        assertThat(response.statusCode()).isEqualTo(200);
        String token = response.jsonPath().getString("access_token");
        assertThat(token).isNotEmpty();
        return token;
    }

    /**
     * Gets a user access token from the test realm, from admin-cli with the pat-management scope.
     * Used for PAT API calls (authenticated against the test realm).
     */
    private String getRealmUserToken(String username, String password) {
        return getRealmUserToken("admin-cli", username, password, PatConstants.PAT_MANAGEMENT_SCOPE);
    }

    /**
     * Gets a user access token from the test realm for a given client, requesting the given scope (null for none).
     */
    private String getRealmUserToken(String clientId, String username, String password, String scope) {
        RequestSpecification request = given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("client_id", clientId)
                .formParam("username", username)
                .formParam("password", password);
        if (scope != null) {
            request.formParam("scope", scope);
        }
        Response response = request.when()
                .post("/realms/" + REALM + "/protocol/openid-connect/token");

        assertThat(response.statusCode()).isEqualTo(200);
        String token = response.jsonPath().getString("access_token");
        assertThat(token).isNotEmpty();
        return token;
    }

    /**
     * Gets a user ID by username using the Keycloak Admin API (master realm token).
     */
    private String getUserId(String username) {
        String masterToken = getMasterAdminToken();
        Response response = given()
                .header("Authorization", "Bearer " + masterToken)
                .when()
                .get("/admin/realms/" + REALM + "/users?username=" + username + "&exact=true");

        assertThat(response.statusCode()).isEqualTo(200);
        String userId = response.jsonPath().getString("[0].id");
        assertThat(userId).isNotEmpty();
        LOGGER.debug("User {} has ID: {}", username, userId);
        return userId;
    }

    private static String getKeycloakBaseUrl() {
        return "http://" + KEYCLOAK_CONTAINER.getHost() + ":" + KEYCLOAK_CONTAINER.getMappedPort(KEYCLOAK_HTTP_PORT);
    }
}
