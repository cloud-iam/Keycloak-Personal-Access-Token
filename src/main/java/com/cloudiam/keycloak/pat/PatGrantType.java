package com.cloudiam.keycloak.pat;

import com.cloudiam.keycloak.pat.config.PatConstants;
import com.cloudiam.keycloak.pat.credentials.PatCredentialModel;
import com.cloudiam.keycloak.pat.credentials.PatCredentialProvider;
import com.cloudiam.keycloak.pat.service.PatRoleResolver;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.encode.AccessTokenContext;
import org.keycloak.protocol.oidc.encode.TokenContextEncoderProvider;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.urls.UrlType;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Exchanges a Personal Access Token for a standard access token narrowed to the PAT's roles.
 */
public class PatGrantType extends OAuth2GrantTypeBase {

    private static final Logger LOGGER = Logger.getLogger(PatGrantType.class);
    public static final String PAT = "pat";

    private final boolean enabled;

    /**
     * @param enabled false refuses every exchange (see {@link PatGrantTypeFactory})
     */
    public PatGrantType(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public Response process(Context context) {
        LOGGER.debug("Processing OAuth2 PAT grant type");
        setContext(context);
        event.detail(Details.AUTH_METHOD, PAT);

        if (!enabled) {
            String errorMessage = "Personal Access Tokens are disabled on this server: they require Keycloak 26.8.2"
                + " or later with the admin audience check enabled and the token-exchange (V1) feature disabled";
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNSUPPORTED_GRANT_TYPE, errorMessage,
                Response.Status.BAD_REQUEST);
        }

        // Only opted-in clients: their mappers may add data the PAT roles do not limit (groups, attributes...)
        if (!client.getClientScopes(true).containsKey(PatConstants.PAT_EXCHANGE_SCOPE)
                && !client.getClientScopes(false).containsKey(PatConstants.PAT_EXCHANGE_SCOPE)) {
            String errorMessage = "Client " + client.getClientId() + " does not accept Personal Access Tokens: assign it"
                + " the " + PatConstants.PAT_EXCHANGE_SCOPE + " client scope";
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNAUTHORIZED_CLIENT, errorMessage,
                Response.Status.BAD_REQUEST);
        }

        try {
            String patValue = formParams.getFirst(PAT);

            if (patValue == null || patValue.trim().isEmpty()) {
                String errorMessage = "Missing PAT parameter in grant request";
                LOGGER.warn(errorMessage);
                event.detail(Details.REASON, errorMessage);
                event.error(Errors.INVALID_REQUEST);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, errorMessage, Response.Status.BAD_REQUEST);
            }

            PatCredentialProvider credentialProvider = (PatCredentialProvider)
                session.getProvider(CredentialProvider.class, PatConstants.CREDENTIAL_TYPE);

            // The owner comes from the token itself, so a bad token costs the same however many PATs exist
            UserModel user = findUserFromTokenFormat(patValue.trim(), realm);
            if (user == null) {
                LOGGER.debug("PAT rejected - no user could be resolved from the token");
                event.error(Errors.USER_NOT_FOUND);
                return createErrorResponse("invalid_grant", "Invalid or expired Personal Access Token");
            }

            PatCredentialModel matchingPat = credentialProvider.findMatchingPat(user, patValue.trim()).orElse(null);
            // Not counted by brute force protection: 256 random bits can't be guessed, and counting would let anyone
            // who knows a user id lock that user out
            if (matchingPat == null) {
                event.user(user);
                event.error(Errors.INVALID_USER_CREDENTIALS);
                LOGGER.debug("Invalid or expired PAT token provided");
                return createErrorResponse("invalid_grant", "Invalid or expired Personal Access Token");
            }

            // Checked after the PAT, so only a valid PAT holder learns the account is disabled
            if (!user.isEnabled()) {
                LOGGER.debugf("PAT authentication refused - user %s is disabled", user.getUsername());
                event.user(user);
                event.error(Errors.USER_DISABLED);
                return createErrorResponse("invalid_grant", "Account disabled");
            }

            if (user.getServiceAccountClientLink() != null) {
                LOGGER.debugf("PAT authentication refused - user %s is a service account", user.getUsername());
                event.user(user);
                event.error(Errors.NOT_ALLOWED);
                return createErrorResponse("invalid_grant", "Service accounts cannot use Personal Access Tokens");
            }

            // Like Keycloak's password grant: an admin-forced action (update password...) must not be skipped
            if (user.getRequiredActionsStream().findAny().isPresent()) {
                LOGGER.debugf("PAT authentication refused - user %s has pending required actions", user.getUsername());
                event.user(user);
                event.error(Errors.RESOLVE_REQUIRED_ACTIONS);
                return createErrorResponse("invalid_grant", "Account is not fully set up");
            }

            credentialProvider.recordUse(user, matchingPat);
            LOGGER.debugf("Valid PAT found - User: %s", user.getUsername());

            event.user(user);
            event.detail(PatConstants.CLAIM_PAT_ID, matchingPat.getId());
            event.detail(PatConstants.CLAIM_PAT_NAME, matchingPat.getName());
            return createPatTokenResponse(user, matchingPat);

        } catch (CorsErrorResponseException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("Error processing PAT grant", e);
            return createErrorResponse("server_error", "Internal server error processing PAT grant");
        }
    }

    /**
     * The owner of a {@code pat_<base64url(userId)>.<base64url(random)>} token, or null if the token is malformed
     * or the user does not exist.
     */
    private UserModel findUserFromTokenFormat(String patValue, RealmModel realm) {
        if (!patValue.startsWith(PatConstants.TOKEN_PREFIX)) {
            return null;
        }
        String withoutPrefix = patValue.substring(PatConstants.TOKEN_PREFIX.length());
        int separatorIndex = withoutPrefix.indexOf(PatConstants.TOKEN_SEPARATOR);
        if (separatorIndex <= 0) {
            return null;
        }

        String encodedUserId = withoutPrefix.substring(0, separatorIndex);
        try {
            String userId = new String(
                Base64.getUrlDecoder().decode(encodedUserId), StandardCharsets.UTF_8);
            return session.users().getUserById(realm, userId);
        } catch (IllegalArgumentException e) {
            LOGGER.debugf("Failed to decode user ID from PAT token: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Builds the token like Keycloak's own grants (transient user session, TokenManager, the client's scopes and
     * mappers), with the roles narrowed to the PAT's.
     */
    private Response createPatTokenResponse(UserModel user, PatCredentialModel pat) {
        String scopeParam = withoutOpenidScope(getRequestedScopes());

        if (!TokenManager.verifyConsentStillAvailable(session, user, client, null, scopeParam)) {
            String errorMessage = "Missing consents for the client " + client.getClientId();
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.CONSENT_DENIED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_SCOPE, errorMessage, Response.Status.BAD_REQUEST);
        }

        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session)
            .createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER,
            Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scopeParam);

        UserSessionModel userSession = new UserSessionManager(session).createUserSession(
            authSession.getParentSession().getId(), realm, user, user.getUsername(),
            clientConnection.getRemoteHost(), PAT, false, null, null,
            UserSessionModel.SessionPersistenceState.TRANSIENT);
        event.session(userSession);

        AuthenticationManager.setClientScopesInSession(session, authSession);
        Map<String, RoleModel> grantedRoles = grantedRoles(user, pat.getPatCredentialData().getRoles());
        Set<String> roleIds = new HashSet<>();
        RoleUtils.expandCompositeRoles(new HashSet<>(grantedRoles.values())).forEach(role -> roleIds.add(role.getId()));
        ClientSessionContext clientSessionCtx = new PatRoleScopedClientSessionContext(
            TokenManager.attachAuthenticationSession(session, userSession, authSession), roleIds);

        TokenManager.AccessTokenResponseBuilder responseBuilder =
            createTokenResponseBuilder(user, userSession, clientSessionCtx, scopeParam, null);

        AccessToken accessToken = responseBuilder.getAccessToken();
        refuseAdminApiAudience(accessToken);
        refuseLightweightToken(accessToken);

        // Keycloak takes a token without session id or role claims for a lightweight one and reloads the user's roles
        if (accessToken.getRealmAccess() == null) {
            accessToken.setRealmAccess(new AccessToken.Access().roles(new HashSet<>()));
        }

        accessToken.getOtherClaims().put(PatConstants.CLAIM_GRANT_TYPE, PatConstants.GRANT_TYPE);
        accessToken.getOtherClaims().put(PatConstants.CLAIM_PAT_ID, pat.getId());
        accessToken.getOtherClaims().put(PatConstants.CLAIM_PAT_NAME, pat.getName());
        accessToken.getOtherClaims().put(PatConstants.CLAIM_PAT_ROLES, new ArrayList<>(grantedRoles.keySet()));

        LOGGER.debugf("Access token created for PAT user: %s", user.getUsername());
        return createTokenResponse(responseBuilder, clientSessionCtx, false);
    }

    /**
     * The Admin API authorizes with the user's stored roles, not the token's: a PAT token must never reach it.
     */
    private void refuseAdminApiAudience(AccessToken token) {
        String adminApiAudience = AdminRoot.realmsUrl(session.getContext().getUri(UrlType.FRONTEND).getBaseUriBuilder())
            .path(realm.getName()).build().toString();
        if (token.hasAudience(adminApiAudience)) {
            String errorMessage = "Personal Access Tokens cannot be exchanged for Admin API tokens (client "
                + client.getClientId() + ")";
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNAUTHORIZED_CLIENT, errorMessage,
                Response.Status.BAD_REQUEST);
        }
    }

    /**
     * No ID token and no userinfo: Keycloak's userinfo refuses tokens without the openid scope, and would otherwise
     * rebuild role claims from all of the user's roles.
     */
    private static String withoutOpenidScope(String scope) {
        if (scope == null) {
            return null;
        }
        return Arrays.stream(scope.split(" "))
            .filter(s -> !s.isEmpty() && !OAuth2Constants.SCOPE_OPENID.equals(s))
            .collect(Collectors.joining(" "));
    }

    /** A lightweight token carries no roles: Keycloak would resolve them from the user wherever it is used. */
    private void refuseLightweightToken(AccessToken token) {
        AccessTokenContext context = session.getProvider(TokenContextEncoderProvider.class)
            .getTokenContextFromTokenId(token.getId());
        if (context.getTokenType() == AccessTokenContext.TokenType.LIGHTWEIGHT) {
            String errorMessage = "Personal Access Tokens cannot be exchanged by a client issuing lightweight access"
                + " tokens (client " + client.getClientId() + ")";
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNAUTHORIZED_CLIENT, errorMessage,
                Response.Status.BAD_REQUEST);
        }
    }

    /**
     * The PAT's roles the token carries, by spec: those still resolving to a single role the user holds. Specs that
     * became unknown, ambiguous or no longer held are dropped, from the roles and from the pat_roles claim alike.
     */
    private Map<String, RoleModel> grantedRoles(UserModel user, List<String> roleSpecs) {
        Map<String, RoleModel> granted = new LinkedHashMap<>();
        for (String roleSpec : roleSpecs) {
            try {
                RoleModel role = PatRoleResolver.resolveRole(realm, roleSpec);
                if (user.hasRole(role)) {
                    granted.put(roleSpec, role);
                } else {
                    LOGGER.debugf("PAT role %s no longer held by %s, skipped", roleSpec, user.getId());
                }
            } catch (BadRequestException e) {
                LOGGER.debugf("PAT role %s not found or ambiguous, skipped", roleSpec);
            }
        }
        return granted;
    }

    /** No refresh token: it would outlive the PAT's revocation or expiry. */
    @Override
    protected boolean useRefreshToken() {
        return false;
    }

    private Response createErrorResponse(String error, String description) {
        return cors.add(Response.status(Response.Status.BAD_REQUEST)
            .type(MediaType.APPLICATION_JSON_TYPE)
            .entity(Map.of(
                "error", error,
                "error_description", description
            )));
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    /** Gives the {@code pat} parameter the larger length limit of grant-specific parameters. */
    @Override
    public Set<String> getTokenParameterNames() {
        return Set.of(PAT);
    }

    @Override
    public void close() {
    }
}
