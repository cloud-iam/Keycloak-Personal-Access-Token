package com.cloudiam.keycloak.pat.guard;

import com.cloudiam.keycloak.pat.config.PatConstants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProvider;
import org.keycloak.representations.AccessToken;

/**
 * Keycloak's access token introspection, returning tokens obtained with a PAT unchanged. Keycloak otherwise rebuilds
 * their claims from all of the user's roles, both for introspection and for the Account API.
 */
public class PatSafeAccessTokenIntrospectionProvider extends AccessTokenIntrospectionProvider<AccessToken> {

    public PatSafeAccessTokenIntrospectionProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, UserSessionModel userSession) {
        if (token.getOtherClaims().containsKey(PatConstants.CLAIM_PAT_ID)) {
            return token;
        }
        return super.transformAccessToken(token, userSession);
    }
}
