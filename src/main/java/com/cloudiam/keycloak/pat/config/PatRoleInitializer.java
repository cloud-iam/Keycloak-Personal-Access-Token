package com.cloudiam.keycloak.pat.config;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

/**
 * Creates the {@code pat-management} and {@code pat-exchange} client scopes. An existing scope is left untouched,
 * so an admin's changes are kept.
 */
public final class PatRoleInitializer {

    private static final Logger LOGGER = Logger.getLogger(PatRoleInitializer.class);

    private PatRoleInitializer() {
    }

    /** Creates {@code pat-management} as an optional scope of admin-cli. */
    public static void ensurePatManagementScope(RealmModel realm) {
        if (KeycloakModelUtils.getClientScopeByName(realm, PatConstants.PAT_MANAGEMENT_SCOPE) != null) {
            LOGGER.debugf("Client scope '%s' already exists in realm '%s'",
                PatConstants.PAT_MANAGEMENT_SCOPE, realm.getName());
            return;
        }

        ClientScopeModel scope = realm.addClientScope(PatConstants.PAT_MANAGEMENT_SCOPE);
        scope.setDescription(PatConstants.PAT_MANAGEMENT_SCOPE_DESCRIPTION);
        scope.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        scope.setIncludeInTokenScope(true);
        scope.setDisplayOnConsentScreen(true);
        scope.setConsentScreenText("Manage your personal access tokens");

        ClientModel adminCli = realm.getClientByClientId(Constants.ADMIN_CLI_CLIENT_ID);
        if (adminCli != null) {
            adminCli.addClientScope(scope, false);
        }
        LOGGER.infof("Created '%s' client scope in realm '%s'", PatConstants.PAT_MANAGEMENT_SCOPE, realm.getName());
    }

    /** Creates {@code pat-exchange}, assigned to no client and left out of the token's scope claim. */
    public static void ensurePatExchangeScope(RealmModel realm) {
        if (KeycloakModelUtils.getClientScopeByName(realm, PatConstants.PAT_EXCHANGE_SCOPE) != null) {
            LOGGER.debugf("Client scope '%s' already exists in realm '%s'",
                PatConstants.PAT_EXCHANGE_SCOPE, realm.getName());
            return;
        }

        ClientScopeModel scope = realm.addClientScope(PatConstants.PAT_EXCHANGE_SCOPE);
        scope.setDescription(PatConstants.PAT_EXCHANGE_SCOPE_DESCRIPTION);
        scope.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        scope.setIncludeInTokenScope(false);
        scope.setDisplayOnConsentScreen(false);
        LOGGER.infof("Created '%s' client scope in realm '%s'", PatConstants.PAT_EXCHANGE_SCOPE, realm.getName());
    }
}
