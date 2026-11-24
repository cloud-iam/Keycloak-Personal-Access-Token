package com.cloudiam.keycloak.pat.rest;

import com.cloudiam.keycloak.pat.config.PatConstants;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import org.jboss.logging.Logger;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.TokenUtil;

/**
 * Serves the PAT API at /realms/{realm}/pat to bearer tokens with the pat-management scope.
 */
public class PatResourceProvider implements RealmResourceProvider {

    private static final Logger LOGGER = Logger.getLogger(PatResourceProvider.class);

    private final KeycloakSession session;

    public PatResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        RealmModel realm = session.getContext().getRealm();

        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
            .authenticate();

        if (authResult == null) {
            LOGGER.debug("PAT API access denied - no valid bearer token");
            throw new NotAuthorizedException("Bearer token required");
        }

        // Otherwise a leaked PAT could mint PATs with more roles that outlive its own revocation
        if (authResult.getToken().getOtherClaims().containsKey(PatConstants.CLAIM_PAT_ID)) {
            LOGGER.debugf("PAT API access denied - token of user %s was obtained with a PAT",
                authResult.getUser().getUsername());
            throw new ForbiddenException("Tokens obtained with a Personal Access Token cannot manage Personal Access Tokens");
        }

        // Otherwise any token of the realm (third-party app, stolen short-lived token) could become a long-lived PAT
        if (!TokenUtil.hasScope(authResult.getToken().getScope(), PatConstants.PAT_MANAGEMENT_SCOPE)) {
            LOGGER.debugf("PAT API access denied - token of user %s (client %s) lacks the %s scope",
                authResult.getUser().getUsername(), authResult.getClient().getClientId(),
                PatConstants.PAT_MANAGEMENT_SCOPE);
            throw new ForbiddenException("Managing Personal Access Tokens requires a token with the "
                + PatConstants.PAT_MANAGEMENT_SCOPE + " scope");
        }

        // A PAT would outlive the rotation of the client's secret
        if (authResult.getUser().getServiceAccountClientLink() != null) {
            LOGGER.debugf("PAT API access denied - %s is a service account", authResult.getUser().getUsername());
            throw new ForbiddenException("Service accounts cannot manage Personal Access Tokens");
        }

        // An admin impersonating a user must not get a PAT acting as that user
        if (authResult.getSession() != null
                && authResult.getSession().getNote(ImpersonationSessionNote.IMPERSONATOR_ID.toString()) != null) {
            LOGGER.debugf("PAT API access denied - session of user %s is impersonated", authResult.getUser().getUsername());
            throw new ForbiddenException("Impersonated sessions cannot manage Personal Access Tokens");
        }

        LOGGER.debugf("PAT API access by user: %s", authResult.getUser().getUsername());

        return new PatResource(session, realm, authResult);
    }

    @Override
    public void close() {
    }
}
