package com.cloudiam.keycloak.pat.guard;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantTypeFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;

/** Replaces Keycloak's JWT authorization grant: same id, higher order. */
public class PatSafeJWTAuthorizationGrantTypeFactory extends JWTAuthorizationGrantTypeFactory {

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new PatSafeJWTAuthorizationGrantType();
    }

    @Override
    public int order() {
        return 1;
    }
}
