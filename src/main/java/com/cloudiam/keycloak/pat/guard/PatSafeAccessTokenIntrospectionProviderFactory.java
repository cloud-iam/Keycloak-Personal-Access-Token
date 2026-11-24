package com.cloudiam.keycloak.pat.guard;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;

/** Replaces Keycloak's access token introspection: same id, higher order. */
public class PatSafeAccessTokenIntrospectionProviderFactory extends AccessTokenIntrospectionProviderFactory {

    @Override
    public TokenIntrospectionProvider create(KeycloakSession session) {
        return new PatSafeAccessTokenIntrospectionProvider(session);
    }

    @Override
    public int order() {
        return 1;
    }
}
