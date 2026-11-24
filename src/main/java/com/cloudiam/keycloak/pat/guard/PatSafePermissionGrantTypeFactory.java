package com.cloudiam.keycloak.pat.guard;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.PermissionGrantTypeFactory;

/** Replaces Keycloak's UMA (uma-ticket) grant: same id, higher order. */
public class PatSafePermissionGrantTypeFactory extends PermissionGrantTypeFactory {

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new PatSafePermissionGrantType();
    }

    @Override
    public int order() {
        return 1;
    }
}
