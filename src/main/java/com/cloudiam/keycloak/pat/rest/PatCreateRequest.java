package com.cloudiam.keycloak.pat.rest;

import com.cloudiam.keycloak.pat.config.PatConstants;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Body of POST /pat. Unknown fields such as userId are rejected: the API only manages the caller's PATs.
 * expirationDays defaults to 90 when omitted; an explicit null creates a PAT that never expires.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public class PatCreateRequest {

    @JsonProperty("name")
    private String name;

    @JsonProperty("expirationDays")
    private Integer expirationDays = PatConstants.DEFAULT_EXPIRATION_DAYS;

    @JsonProperty("roles")
    private List<String> roles;

    public PatCreateRequest() {
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getExpirationDays() {
        return expirationDays;
    }

    public void setExpirationDays(Integer expirationDays) {
        this.expirationDays = expirationDays;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
