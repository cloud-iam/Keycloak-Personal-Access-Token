package com.cloudiam.keycloak.pat.guard;

import jakarta.ws.rs.core.Response;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantType;

/** Keycloak's JWT authorization grant (jwt-bearer), refusing tokens obtained with a PAT. */
public class PatSafeJWTAuthorizationGrantType extends JWTAuthorizationGrantType {

    @Override
    public Response process(Context context) {
        PatTokenGuard.refusePatTokens(context);
        return super.process(context);
    }
}
