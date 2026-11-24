package com.cloudiam.keycloak.pat.guard;

import jakarta.ws.rs.core.Response;
import org.keycloak.protocol.oidc.grants.PermissionGrantType;

/** Keycloak's UMA (uma-ticket) grant, refusing tokens obtained with a PAT. */
public class PatSafePermissionGrantType extends PermissionGrantType {

    @Override
    public Response process(Context context) {
        PatTokenGuard.refusePatTokens(context);
        return super.process(context);
    }
}
