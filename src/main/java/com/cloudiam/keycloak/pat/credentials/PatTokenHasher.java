package com.cloudiam.keycloak.pat.credentials;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

/**
 * SHA-256 hashing of PAT values. A PAT carries 32 random bytes, so a fast hash is enough: a slow password hash
 * only matters for secrets people choose.
 *
 * Stored secret data: {@code {"value": "<base64url(sha256(token))>"}}.
 */
public final class PatTokenHasher {

    private static final Logger LOGGER = Logger.getLogger(PatTokenHasher.class);
    private static final String VALUE = "value";
    private static final int SHA256_BYTES = 32;

    private PatTokenHasher() {
    }

    public static byte[] digest(String token) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** The secret data to store for a token. The token itself is never stored. */
    public static String secretData(String token) {
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(digest(token));
        try {
            return JsonSerialization.writeValueAsString(Map.of(VALUE, encoded));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize PAT secret data", e);
        }
    }

    /** Constant-time comparison of a token digest with stored secret data. */
    public static boolean matches(byte[] digest, String secretData) {
        byte[] stored = storedHash(secretData);
        return stored != null && MessageDigest.isEqual(digest, stored);
    }

    /** Whether secret data holds a SHA-256 hash in the format {@link #secretData(String)} produces. */
    public static boolean isHash(String secretData) {
        byte[] stored = storedHash(secretData);
        return stored != null && stored.length == SHA256_BYTES;
    }

    private static byte[] storedHash(String secretData) {
        if (secretData == null) {
            LOGGER.warn("PAT secret data is missing");
            return null;
        }
        try {
            JsonNode value = JsonSerialization.mapper.readTree(secretData).get(VALUE);
            if (value == null || !value.isTextual()) {
                LOGGER.warn("PAT secret data has no hash value");
                return null;
            }
            return Base64.getUrlDecoder().decode(value.asText());
        } catch (IOException | IllegalArgumentException e) {
            LOGGER.warnf("PAT secret data is unreadable: %s", e.getMessage());
            return null;
        }
    }
}
