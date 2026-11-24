package com.cloudiam.keycloak.pat.credentials;

import com.cloudiam.keycloak.pat.config.PatConstants;
import org.keycloak.Config;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for {@link PatCredentialProvider}.
 * Registered via META-INF/services and identified by {@link PatConstants#CREDENTIAL_TYPE}.
 */
public class PatCredentialProviderFactory implements CredentialProviderFactory<PatCredentialProvider> {

    @Override
    public String getId() {
        return PatConstants.CREDENTIAL_TYPE;
    }

    @Override
    public PatCredentialProvider create(KeycloakSession session) {
        return new PatCredentialProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration required
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization required
    }

    @Override
    public void close() {
        // No resources to close
    }
}
