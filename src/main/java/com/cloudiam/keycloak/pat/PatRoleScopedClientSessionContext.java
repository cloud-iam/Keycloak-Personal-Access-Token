package com.cloudiam.keycloak.pat;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.rar.AuthorizationRequestContext;

import java.util.Set;
import java.util.stream.Stream;

/**
 * Keycloak's client session context with the roles narrowed to the PAT's. Every role mapper reads roles from
 * {@link #getRolesStream()}, so all role-derived claims are narrowed (realm_access, resource_access, groups...).
 */
final class PatRoleScopedClientSessionContext implements ClientSessionContext {

    private final ClientSessionContext delegate;
    private final Set<String> patRoleIds;

    PatRoleScopedClientSessionContext(ClientSessionContext delegate, Set<String> patRoleIds) {
        this.delegate = delegate;
        this.patRoleIds = Set.copyOf(patRoleIds);
    }

    /** The roles Keycloak computed for the user and client, kept only if the PAT has them. */
    @Override
    public Stream<RoleModel> getRolesStream() {
        return delegate.getRolesStream().filter(role -> patRoleIds.contains(role.getId()));
    }

    @Override
    public AuthenticatedClientSessionModel getClientSession() {
        return delegate.getClientSession();
    }

    @Override
    public Set<String> getClientScopeIds() {
        return delegate.getClientScopeIds();
    }

    @Override
    public Stream<ClientScopeModel> getClientScopesStream() {
        return delegate.getClientScopesStream();
    }

    @Override
    public boolean isOfflineTokenRequested() {
        return delegate.isOfflineTokenRequested();
    }

    @Override
    public Stream<ProtocolMapperModel> getProtocolMappersStream() {
        return delegate.getProtocolMappersStream();
    }

    @Override
    public String getScopeString() {
        return delegate.getScopeString();
    }

    @Override
    public String getScopeString(boolean ignoreIncludeInTokenScope) {
        return delegate.getScopeString(ignoreIncludeInTokenScope);
    }

    @Override
    public void setAttribute(String name, Object value) {
        delegate.setAttribute(name, value);
    }

    @Override
    public <T> T getAttribute(String attribute, Class<T> clazz) {
        return delegate.getAttribute(attribute, clazz);
    }

    @Override
    public AuthorizationRequestContext getAuthorizationRequestContext() {
        return delegate.getAuthorizationRequestContext();
    }
}
