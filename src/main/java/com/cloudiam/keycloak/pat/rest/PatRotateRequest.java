package com.cloudiam.keycloak.pat.rest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Body of POST /pat/{id}/rotate. Unknown fields are rejected.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public class PatRotateRequest {

    @JsonProperty("expirationDays")
    private Integer expirationDays;

    public PatRotateRequest() {
    }

    public Integer getExpirationDays() {
        return expirationDays;
    }

    public void setExpirationDays(Integer expirationDays) {
        this.expirationDays = expirationDays;
    }
}
