package com.cloudiam.keycloak.pat;

import com.cloudiam.keycloak.pat.config.PatConstants;
import com.cloudiam.keycloak.pat.guard.PatSafeAccessTokenIntrospectionProviderFactory;
import com.cloudiam.keycloak.pat.guard.PatSafeJWTAuthorizationGrantTypeFactory;
import com.cloudiam.keycloak.pat.guard.PatSafePermissionGrantTypeFactory;
import com.cloudiam.keycloak.pat.guard.PatSafeTokenExchangeGrantTypeFactory;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.services.resources.admin.AdminRoot;

import java.util.Arrays;

/**
 * Registers the PAT grant. Its id is the grant type URI, which Keycloak matches against the grant_type parameter.
 */
public class PatGrantTypeFactory implements OAuth2GrantTypeFactory {
    private static final Logger LOGGER = Logger.getLogger(PatGrantTypeFactory.class);

    private boolean enabled;

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new PatGrantType(enabled);
    }

    @Override
    public void init(Config.Scope config) {
        boolean adminApiProtected = isAdminApiProtected();
        boolean legacyTokenExchange = Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE);
        enabled = adminApiProtected && !legacyTokenExchange;
        if (!adminApiProtected) {
            LOGGER.error("Personal Access Token exchange is DISABLED: this Keycloak accepts any realm token on its"
                + " Admin API and authorizes it with the user's stored roles, so a PAT would carry all of its"
                + " owner's admin rights whatever roles it was given. Use Keycloak 26.8.2 or later with the"
                + " admin audience check enabled (do not set admin audienceCheckEnabled to false).");
        }
        if (legacyTokenExchange) {
            LOGGER.error("Personal Access Token exchange is DISABLED: the token-exchange (V1) preview feature is"
                + " enabled. It lets clients swap a token obtained with a PAT for a new one carrying all of its"
                + " owner's roles. Disable the token-exchange feature; standard token exchange (V2) is supported.");
        }
    }

    /**
     * Whether the Admin API rejects tokens without its audience (Keycloak 26.8.2+, unless turned off). Detected from
     * the check itself rather than the version, which downstream builds may change.
     */
    static boolean isAdminApiProtected() {
        boolean checkExists = Arrays.stream(AdminRoot.class.getDeclaredMethods())
            .anyMatch(method -> "isAudienceCheckEnabled".equals(method.getName()));
        Boolean checkEnabled = Config.scope("admin").getBoolean("audienceCheckEnabled", true);
        return checkExists && Boolean.TRUE.equals(checkEnabled);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        boolean guarded = isGuarded(factory, OAuth2GrantType.class, new PatSafeTokenExchangeGrantTypeFactory())
            && isGuarded(factory, OAuth2GrantType.class, new PatSafePermissionGrantTypeFactory())
            && isGuarded(factory, OAuth2GrantType.class, new PatSafeJWTAuthorizationGrantTypeFactory())
            && isGuarded(factory, TokenIntrospectionProvider.class, new PatSafeAccessTokenIntrospectionProviderFactory());
        if (!guarded) {
            enabled = false;
        }
    }

    /**
     * Whether the provider Keycloak uses for this id is ours (or absent, e.g. token exchange turned off). Another
     * extension replacing it with a higher order would drop the check on PAT tokens.
     */
    private static <T extends Provider> boolean isGuarded(KeycloakSessionFactory factory, Class<T> spi,
                                                          ProviderFactory<T> guard) {
        ProviderFactory<T> active = factory.getProviderFactory(spi, guard.getId());
        if (active == null || active.getClass() == guard.getClass()) {
            return true;
        }
        LOGGER.errorf("Personal Access Token exchange is DISABLED: %s is provided by %s instead of %s, so tokens"
            + " obtained with a PAT could get all of their owner's roles. Remove the extension replacing it.", guard.getId(), active.getClass().getName(), guard.getClass().getName());
        return false;
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PatConstants.GRANT_TYPE;
    }

    /** Grant shortcut Keycloak puts in the jti: exactly 2 characters, distinct from the built-in grants'. */
    @Override
    public String getShortcut() {
        return "pa";
    }
}
