package com.cloudiam.keycloak.pat.guard;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.TokenExchangeGrantTypeFactory;

/** Replaces Keycloak's token exchange grant: same id, higher order. */
public class PatSafeTokenExchangeGrantTypeFactory extends TokenExchangeGrantTypeFactory {

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new PatSafeTokenExchangeGrantType();
    }

    @Override
    public int order() {
        return 1;
    }
}
