package com.cloudiam.keycloak.pat.service;

import com.cloudiam.keycloak.pat.config.PatConstants;
import jakarta.ws.rs.BadRequestException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves PAT role specs: "roleName" for a realm role, "clientId:roleName" for a client role.
 */
public final class PatRoleResolver {

    private PatRoleResolver() {
    }

    /**
     * A realm role, or a client role as "clientId:roleName". Client ids and role names may contain ':' too (URN client
     * ids, "app:read" realm roles), so every reading is tried; a spec matching several roles is refused rather than
     * guessed.
     *
     * @throws BadRequestException if no role, or more than one, matches
     */
    public static RoleModel resolveRole(RealmModel realm, String roleSpec) {
        List<RoleModel> matches = new ArrayList<>();
        RoleModel realmRole = realm.getRole(roleSpec);
        if (realmRole != null) {
            matches.add(realmRole);
        }
        for (int i = roleSpec.indexOf(':'); i > 0; i = roleSpec.indexOf(':', i + 1)) {
            ClientModel client = realm.getClientByClientId(roleSpec.substring(0, i));
            RoleModel role = client != null ? client.getRole(roleSpec.substring(i + 1)) : null;
            if (role != null) {
                matches.add(role);
            }
        }
        if (matches.isEmpty()) {
            throw new BadRequestException("Role not found: " + roleSpec);
        }
        if (matches.size() > 1) {
            throw new BadRequestException("Ambiguous role: " + roleSpec + " matches several roles");
        }
        return matches.get(0);
    }

    /**
     * @return the trimmed role specs, blank ones and duplicates dropped
     * @throws BadRequestException if there are too many roles, a role does not exist or the user does not have it
     */
    public static List<String> validateRoles(RealmModel realm, UserModel user, List<String> requestedRoles) {
        if (requestedRoles == null || requestedRoles.isEmpty()) {
            return new ArrayList<>();
        }

        if (requestedRoles.size() > PatConstants.MAX_ROLES_PER_PAT) {
            throw new BadRequestException("roles must not exceed " + PatConstants.MAX_ROLES_PER_PAT + " entries");
        }

        Set<String> validatedRoles = new LinkedHashSet<>();
        for (String roleSpec : requestedRoles) {
            if (roleSpec == null || roleSpec.trim().isEmpty()) {
                continue;
            }
            String trimmed = roleSpec.trim();
            RoleModel role = resolveRole(realm, trimmed);
            if (!user.hasRole(role)) {
                throw new BadRequestException("User does not have role: " + trimmed);
            }
            validatedRoles.add(trimmed);
        }
        return new ArrayList<>(validatedRoles);
    }
}
