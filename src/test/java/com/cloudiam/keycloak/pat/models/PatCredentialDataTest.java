package com.cloudiam.keycloak.pat.models;

import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PatCredentialDataTest {

    @Test
    void defaultConstructorShouldSetDefaults() {
        PatCredentialData data = new PatCredentialData();

        assertThat(data.getCreatedAt()).isNotNull();
        assertThat(data.getRoles()).isEmpty();
        assertThat(data.getExpiresAt()).isNull();
        assertThat(data.getName()).isNull();
    }

    @Test
    void parameterizedConstructorShouldSetFields() {
        Instant expires = Instant.now().plus(90, ChronoUnit.DAYS);
        List<String> roles = List.of("admin", "test-app:editor");

        PatCredentialData data = new PatCredentialData("My Token", roles, expires);

        assertThat(data.getName()).isEqualTo("My Token");
        assertThat(data.getRoles()).containsExactly("admin", "test-app:editor");
        assertThat(data.getExpiresAt()).isEqualTo(expires);
    }

    @Test
    void constructorShouldDefensiveCopyRoles() {
        ArrayList<String> mutableRoles = new ArrayList<>(List.of("role1"));
        PatCredentialData data = new PatCredentialData("Token", mutableRoles, null);

        mutableRoles.add("role2");
        assertThat(data.getRoles()).containsExactly("role1");
    }

    @Test
    void getRolesShouldReturnUnmodifiableList() {
        PatCredentialData data = new PatCredentialData("Token", List.of("role1"), null);

        assertThatThrownBy(() -> data.getRoles().add("hack"))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void getRolesShouldReturnEmptyListWhenNull() {
        PatCredentialData data = new PatCredentialData();
        data.setRoles(null);

        assertThat(data.getRoles()).isEmpty();
    }

    @Test
    void isExpiredShouldReturnFalseWhenNoExpiration() {
        PatCredentialData data = new PatCredentialData();

        assertThat(data.isExpired()).isFalse();
    }

    @Test
    void isExpiredShouldReturnFalseWhenFutureExpiration() {
        PatCredentialData data = new PatCredentialData();
        data.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

        assertThat(data.isExpired()).isFalse();
    }

    @Test
    void isExpiredShouldReturnTrueWhenPastExpiration() {
        PatCredentialData data = new PatCredentialData();
        data.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));

        assertThat(data.isExpired()).isTrue();
    }

    @Test
    void toJsonShouldProduceValidJson() {
        PatCredentialData data = new PatCredentialData("Test", List.of("role1"), null);

        String json = data.toJson();

        assertThat(json).contains("\"name\":\"Test\"")
                .contains("\"roles\":[\"role1\"]");
    }

    @Test
    void jsonRoundTripShouldPreserveData() throws Exception {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        PatCredentialData original = new PatCredentialData("My PAT", List.of("admin", "user"), now.plus(30, ChronoUnit.DAYS));
        original.setCreatedAt(now);
        original.setLastUsedAt(now);

        String json = JsonSerialization.writeValueAsString(original);
        PatCredentialData deserialized = JsonSerialization.readValue(json, PatCredentialData.class);

        assertThat(deserialized.getName()).isEqualTo("My PAT");
        assertThat(deserialized.getRoles()).containsExactly("admin", "user");
        assertThat(deserialized.getCreatedAt()).isEqualTo(now);
        assertThat(deserialized.getExpiresAt()).isEqualTo(now.plus(30, ChronoUnit.DAYS));
        assertThat(deserialized.getLastUsedAt()).isEqualTo(now);
    }

    @Test
    void jsonDeserializationShouldIgnoreUnknownFields() throws Exception {
        String json = "{\"name\":\"Token\",\"unknownField\":\"value\",\"roles\":[]}";
        PatCredentialData data = JsonSerialization.readValue(json, PatCredentialData.class);

        assertThat(data.getName()).isEqualTo("Token");
    }

    @Test
    void settersShouldDefensiveCopyRoles() {
        ArrayList<String> mutableRoles = new ArrayList<>(List.of("role1"));
        PatCredentialData data = new PatCredentialData();
        data.setRoles(mutableRoles);

        mutableRoles.add("role2");
        assertThat(data.getRoles()).containsExactly("role1");
    }
}
