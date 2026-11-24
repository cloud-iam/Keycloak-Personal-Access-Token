package com.cloudiam.keycloak.pat.rest;

import com.cloudiam.keycloak.pat.config.PatConstants;
import com.cloudiam.keycloak.pat.credentials.PatTokenHasher;
import com.cloudiam.keycloak.pat.models.PatCredentialData;
import com.cloudiam.keycloak.pat.service.PatRoleResolver;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * PAT API at /realms/{realm}/pat. Every endpoint works on the authenticated user's PATs only; admins revoke PATs
 * through the user's credentials in the Admin API.
 */
public class PatResource {

    private static final Logger LOGGER = Logger.getLogger(PatResource.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String RESOURCE_TYPE_PAT = "PERSONAL_ACCESS_TOKEN";

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AuthenticationManager.AuthResult auth;
    private final AdminEventBuilder adminEvent;

    public PatResource(KeycloakSession session, RealmModel realm, AuthenticationManager.AuthResult auth) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        AdminAuth adminAuth = new AdminAuth(realm, auth.getToken(), auth.getUser(), auth.getClient());
        this.adminEvent = new AdminEventBuilder(realm, adminAuth, session,
            session.getContext().getConnection())
            .resource(RESOURCE_TYPE_PAT);
    }

    /** Creates a PAT. expirationDays defaults to 90; null means it never expires. */
    @POST
    @Path("")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createPat(PatCreateRequest request) {
        LOGGER.debugf("PAT creation request by user: %s", auth.getUser().getUsername());

        try {
            validateCreateRequest(request);

            UserModel targetUser = auth.getUser();
            checkPatLimit(targetUser);
            checkDuplicateName(request.getName(), targetUser);
            List<String> validatedRoles = PatRoleResolver.validateRoles(realm, targetUser, request.getRoles());
            Instant expiresAt = computeExpiration(request.getExpirationDays());

            TokenHashResult tokenHash = generateAndHashToken(targetUser.getId());

            PatCredentialData credentialData = new PatCredentialData(
                request.getName(), validatedRoles, expiresAt);

            CredentialModel model = new CredentialModel();
            model.setType(PatConstants.CREDENTIAL_TYPE);
            model.setCreatedDate(Time.currentTimeMillis());
            model.setUserLabel(request.getName());
            model.setSecretData(tokenHash.secretData);
            model.setCredentialData(credentialData.toJson());

            CredentialModel storedCredential = targetUser.credentialManager().createStoredCredential(model);

            LOGGER.infof("PAT created - User: %s, PAT ID: %s, Name: %s, Roles: %s",
                targetUser.getUsername(), storedCredential.getId(), request.getName(), validatedRoles);

            adminEvent.operation(OperationType.CREATE)
                .resourcePath("users", targetUser.getId(), "pat", storedCredential.getId())
                .representation(toAuditRepresentation(
                    storedCredential.getId(), request.getName(), validatedRoles,
                    credentialData.getCreatedAt(), expiresAt))
                .success();

            PatCreateResponse response = new PatCreateResponse(
                storedCredential.getId(),
                request.getName(),
                tokenHash.plainToken,
                validatedRoles,
                credentialData.getCreatedAt(),
                expiresAt
            );

            return Response.status(Response.Status.CREATED).entity(response).build();

        } catch (Exception e) {
            return handleException(e, "creating PAT");
        }
    }

    /** Replaces the token value, invalidating the old one. Keeps the expiration unless expirationDays is given. */
    @POST
    @Path("/{id}/rotate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response rotatePat(@PathParam("id") String credentialId, PatRotateRequest request) {
        LOGGER.debugf("PAT rotation request by user: %s, credential: %s",
            auth.getUser().getUsername(), credentialId);

        try {
            Integer expirationDays = request != null ? request.getExpirationDays() : null;
            validateExpirationDays(expirationDays);

            UserModel targetUser = auth.getUser();

            CredentialModel existingCredential = targetUser.credentialManager()
                .getStoredCredentialById(credentialId);
            if (existingCredential == null
                    || !PatConstants.CREDENTIAL_TYPE.equals(existingCredential.getType())) {
                throw new NotFoundException("PAT not found: " + credentialId);
            }

            PatCredentialData credentialData;
            try {
                credentialData = JsonSerialization
                    .readValue(existingCredential.getCredentialData(), PatCredentialData.class);
            } catch (IOException e) {
                throw new BadRequestException("Failed to read PAT metadata");
            }

            TokenHashResult tokenHash = generateAndHashToken(targetUser.getId());

            existingCredential.setSecretData(tokenHash.secretData);

            if (expirationDays != null) {
                credentialData.setExpiresAt(computeExpiration(expirationDays));
            }

            credentialData.setLastUsedAt(null);

            existingCredential.setCredentialData(credentialData.toJson());
            targetUser.credentialManager().updateStoredCredential(existingCredential);

            LOGGER.infof("PAT rotated - User: %s, PAT ID: %s, Name: %s",
                targetUser.getUsername(), credentialId, credentialData.getName());

            adminEvent.operation(OperationType.ACTION)
                .resourcePath("users", targetUser.getId(), "pat", credentialId, "rotate")
                .representation(toAuditRepresentation(
                    credentialId, credentialData.getName(), credentialData.getRoles(),
                    credentialData.getCreatedAt(), credentialData.getExpiresAt()))
                .success();

            PatCreateResponse response = new PatCreateResponse(
                credentialId,
                credentialData.getName(),
                tokenHash.plainToken,
                credentialData.getRoles(),
                credentialData.getCreatedAt(),
                credentialData.getExpiresAt()
            );

            return Response.ok(response).build();

        } catch (Exception e) {
            return handleException(e, "rotating PAT");
        }
    }

    @GET
    @Path("")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listPats() {
        LOGGER.debugf("PAT list request by user: %s", auth.getUser().getUsername());

        try {
            UserModel targetUser = auth.getUser();

            List<PatItemResponse> items = targetUser.credentialManager()
                .getStoredCredentialsByTypeStream(PatConstants.CREDENTIAL_TYPE)
                .map(this::toItemResponse)
                .toList();

            LOGGER.debugf("Returning %d PATs for user: %s", items.size(), targetUser.getUsername());
            return Response.ok(items).build();

        } catch (Exception e) {
            return handleException(e, "listing PATs");
        }
    }

    @GET
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPat(@PathParam("id") String credentialId) {
        LOGGER.debugf("PAT get request by user: %s, credential: %s",
            auth.getUser().getUsername(), credentialId);

        try {
            UserModel targetUser = auth.getUser();

            CredentialModel credential = targetUser.credentialManager()
                .getStoredCredentialById(credentialId);
            if (credential == null
                    || !PatConstants.CREDENTIAL_TYPE.equals(credential.getType())) {
                throw new NotFoundException("PAT not found: " + credentialId);
            }

            return Response.ok(toItemResponse(credential)).build();

        } catch (Exception e) {
            return handleException(e, "getting PAT");
        }
    }

    @DELETE
    @Path("/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deletePat(@PathParam("id") String credentialId) {
        LOGGER.debugf("PAT delete request by user: %s, credential: %s",
            auth.getUser().getUsername(), credentialId);

        try {
            UserModel targetUser = auth.getUser();

            CredentialModel credential = targetUser.credentialManager()
                .getStoredCredentialById(credentialId);
            if (credential == null
                    || !PatConstants.CREDENTIAL_TYPE.equals(credential.getType())) {
                throw new NotFoundException("PAT not found: " + credentialId);
            }

            boolean deleted = targetUser.credentialManager()
                .removeStoredCredentialById(credentialId);

            if (!deleted) {
                throw new RuntimeException("Failed to delete PAT: " + credentialId);
            }

            LOGGER.infof("PAT deleted - User: %s, PAT ID: %s", targetUser.getUsername(), credentialId);

            adminEvent.operation(OperationType.DELETE)
                .resourcePath("users", targetUser.getId(), "pat", credentialId)
                .success();

            return Response.noContent().build();

        } catch (Exception e) {
            return handleException(e, "deleting PAT");
        }
    }

    private void validateCreateRequest(PatCreateRequest request) {
        if (request == null) {
            throw new BadRequestException("Request body is required");
        }
        validateName(request.getName());
        request.setName(request.getName().trim());
        validateExpirationDays(request.getExpirationDays());
    }

    private void validateName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new BadRequestException("name is required");
        }
        String trimmedName = name.trim();
        if (trimmedName.length() > PatConstants.MAX_NAME_LENGTH) {
            throw new BadRequestException(
                "name must not exceed " + PatConstants.MAX_NAME_LENGTH + " characters");
        }
        // Control characters could forge log lines
        for (int i = 0; i < trimmedName.length(); i++) {
            if (Character.isISOControl(trimmedName.charAt(i))) {
                throw new BadRequestException("name contains invalid control characters");
            }
        }
    }

    private void validateExpirationDays(Integer expirationDays) {
        if (expirationDays != null) {
            if (expirationDays <= 0) {
                throw new BadRequestException("expirationDays must be positive");
            }
            if (expirationDays > PatConstants.MAX_EXPIRATION_DAYS) {
                throw new BadRequestException("expirationDays must not exceed " + PatConstants.MAX_EXPIRATION_DAYS);
            }
        }
    }

    private void checkPatLimit(UserModel targetUser) {
        long patCount = targetUser.credentialManager()
            .getStoredCredentialsByTypeStream(PatConstants.CREDENTIAL_TYPE)
            .count();
        if (patCount >= PatConstants.MAX_PATS_PER_USER) {
            throw new BadRequestException(
                "Maximum number of PATs reached (" + PatConstants.MAX_PATS_PER_USER + ")");
        }
    }

    private void checkDuplicateName(String name, UserModel targetUser) {
        boolean exists = targetUser.credentialManager()
            .getStoredCredentialsByTypeStream(PatConstants.CREDENTIAL_TYPE)
            .anyMatch(cred -> name.equals(cred.getUserLabel()));
        if (exists) {
            throw new BadRequestException("A PAT with name '" + name + "' already exists for this user");
        }
    }

    private Instant computeExpiration(Integer expirationDays) {
        if (expirationDays == null) {
            return null;
        }
        return Instant.now().plus(expirationDays, ChronoUnit.DAYS);
    }

    private PatItemResponse toItemResponse(CredentialModel credential) {
        PatCredentialData data;
        try {
            data = JsonSerialization.readValue(credential.getCredentialData(), PatCredentialData.class);
        } catch (IOException e) {
            LOGGER.warnf("Failed to parse credential data for PAT %s", credential.getId());
            return new PatItemResponse(credential.getId(), credential.getUserLabel(),
                List.of(), null, null, null, false);
        }

        return new PatItemResponse(
            credential.getId(),
            data.getName(),
            data.getRoles(),
            data.getCreatedAt(),
            data.getExpiresAt(),
            data.getLastUsedAt(),
            !data.isExpired()
        );
    }

    /** Admin event representation: metadata only, never the token or its hash. */
    private Map<String, Object> toAuditRepresentation(String id, String name,
            List<String> roles, Instant createdAt, Instant expiresAt) {
        Map<String, Object> rep = new LinkedHashMap<>();
        rep.put("id", id);
        rep.put("name", name);
        rep.put("roles", roles);
        rep.put("createdAt", createdAt != null ? createdAt.toString() : null);
        rep.put("expiresAt", expiresAt != null ? expiresAt.toString() : null);
        return rep;
    }

    /** A new {@code pat_<base64url(userId)>.<base64url(random)>} token and the secret data to store for it. */
    private TokenHashResult generateAndHashToken(String userId) {
        String encodedUserId = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(userId.getBytes(StandardCharsets.UTF_8));
        byte[] randomBytes = new byte[PatConstants.TOKEN_RANDOM_BYTES];
        SECURE_RANDOM.nextBytes(randomBytes);
        String encodedRandom = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(randomBytes);
        String plainToken = PatConstants.TOKEN_PREFIX + encodedUserId
            + PatConstants.TOKEN_SEPARATOR + encodedRandom;

        return new TokenHashResult(plainToken, PatTokenHasher.secretData(plainToken));
    }

    private Response handleException(Exception e, String operation) {
        if (e instanceof BadRequestException) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(Collections.singletonMap("error", e.getMessage()))
                .build();
        }
        if (e instanceof NotFoundException) {
            return Response.status(Response.Status.NOT_FOUND)
                .entity(Collections.singletonMap("error", e.getMessage()))
                .build();
        }
        if (e instanceof ForbiddenException || e instanceof NotAuthorizedException) {
            return Response.status(Response.Status.FORBIDDEN)
                .entity(Collections.singletonMap("error", e.getMessage()))
                .build();
        }
        LOGGER.errorf(e, "Error %s", operation);
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
            .entity(Collections.singletonMap("error", "Internal server error"))
            .build();
    }

    private static final class TokenHashResult {
        final String plainToken;
        final String secretData;

        TokenHashResult(String plainToken, String secretData) {
            this.plainToken = plainToken;
            this.secretData = secretData;
        }
    }
}