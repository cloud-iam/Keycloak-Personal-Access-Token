package com.cloudiam.keycloak.pat.guard;

import jakarta.ws.rs.core.Response;
import org.keycloak.protocol.oidc.grants.TokenExchangeGrantType;

/** Keycloak's token exchange grant, refusing tokens obtained with a PAT. */
public class PatSafeTokenExchangeGrantType extends TokenExchangeGrantType {

    @Override
    public Response process(Context context) {
        PatTokenGuard.refusePatTokens(context);
        return super.process(context);
    }
}
