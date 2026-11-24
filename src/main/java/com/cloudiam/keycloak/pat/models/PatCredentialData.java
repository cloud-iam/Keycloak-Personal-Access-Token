package com.cloudiam.keycloak.pat.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * PAT metadata, stored as JSON in the credential's credentialData.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PatCredentialData {

    @JsonProperty("name")
    private String name;

    @JsonProperty("roles")
    private List<String> roles;

    @JsonProperty("createdAt")
    private Instant createdAt;

    @JsonProperty("expiresAt")
    private Instant expiresAt;

    @JsonProperty("lastUsedAt")
    private Instant lastUsedAt;

    public PatCredentialData() {
        this.roles = new ArrayList<>();
        this.createdAt = Instant.now();
    }

    public PatCredentialData(String name, List<String> roles, Instant expiresAt) {
        this();
        this.name = name;
        this.roles = roles != null ? new ArrayList<>(roles) : new ArrayList<>();
        this.expiresAt = expiresAt;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getRoles() {
        return roles != null ? Collections.unmodifiableList(roles) : Collections.emptyList();
    }

    public void setRoles(List<String> roles) {
        this.roles = roles != null ? new ArrayList<>(roles) : new ArrayList<>();
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }

    public void setLastUsedAt(Instant lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    /** False when no expiration is set. */
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public String toJson() {
        try {
            return JsonSerialization.writeValueAsString(this);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize PAT credential data", e);
        }
    }
}
