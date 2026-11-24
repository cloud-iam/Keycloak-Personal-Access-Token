package com.cloudiam.keycloak.pat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestConfig.class);

    public static final String REALM = "testcontainer";

    /**
     * Gets the Keycloak Docker image to use for tests.
     * Can be overridden via KEYCLOAK_VERSION environment variable.
     *
     * @return Docker image name (e.g., "quay.io/keycloak/keycloak:26.8.2")
     */
    public static String getKeycloakDockerImage() {
        String version = System.getenv("KEYCLOAK_VERSION");
        if (version == null || version.isEmpty()) {
            version = "26.8.2";
        }
        String dockerImage = "quay.io/keycloak/keycloak:" + version;
        LOGGER.info("Using Keycloak Docker image: {}", dockerImage);
        return dockerImage;
    }
}
