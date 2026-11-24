package com.cloudiam.keycloak.pat.rest;

import com.cloudiam.keycloak.pat.config.PatRoleInitializer;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Registers the PAT API and creates the PAT client scopes at startup and on realm creation.
 */
public class PatResourceProviderFactory implements RealmResourceProviderFactory, ProviderEventListener {

    private static final Logger LOGGER = Logger.getLogger(PatResourceProviderFactory.class);

    public static final String ID = "pat";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new PatResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(this);
    }

    @Override
    public void onEvent(ProviderEvent event) {
        if (event instanceof PostMigrationEvent) {
            handlePostMigrationEvent((PostMigrationEvent) event);
        } else if (event instanceof RealmModel.RealmPostCreateEvent) {
            handleRealmPostCreateEvent((RealmModel.RealmPostCreateEvent) event);
        }
    }

    /**
     * One transaction per realm: when nodes start together, the one losing the race on a scope only rolls back
     * that realm.
     */
    private void handlePostMigrationEvent(PostMigrationEvent event) {
        KeycloakSessionFactory factory = event.getFactory();

        AtomicReference<List<String>> realmIds = new AtomicReference<>(List.of());
        KeycloakModelUtils.runJobInTransaction(factory, session ->
            realmIds.set(session.realms().getRealmsStream().map(RealmModel::getId).toList()));

        for (String realmId : realmIds.get()) {
            try {
                KeycloakModelUtils.runJobInTransaction(factory, session -> {
                    RealmModel realm = session.realms().getRealm(realmId);
                    if (realm != null) {
                        PatRoleInitializer.ensurePatManagementScope(realm);
                        PatRoleInitializer.ensurePatExchangeScope(realm);
                    }
                });
            } catch (Exception e) {
                LOGGER.warnf("Failed to create pat-management and pat-exchange scopes in realm '%s' (possibly created"
                    + " concurrently by another node): %s", realmId, e.getMessage());
            }
        }
    }

    private void handleRealmPostCreateEvent(RealmModel.RealmPostCreateEvent event) {
        RealmModel realm = event.getCreatedRealm();
        try {
            PatRoleInitializer.ensurePatManagementScope(realm);
            PatRoleInitializer.ensurePatExchangeScope(realm);
        } catch (Exception e) {
            LOGGER.errorf(e, "Failed to create pat-management and pat-exchange scopes in newly created realm '%s'",
                realm.getName());
        }
    }

    @Override
    public void close() {
    }
}