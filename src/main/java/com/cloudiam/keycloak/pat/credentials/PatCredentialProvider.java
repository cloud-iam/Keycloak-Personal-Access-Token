package com.cloudiam.keycloak.pat.credentials;

import com.cloudiam.keycloak.pat.config.PatConstants;
import com.cloudiam.keycloak.pat.models.PatCredentialData;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import java.time.Instant;
import java.util.Optional;

/**
 * Stores PATs as Keycloak user credentials and matches token values against them.
 */
public class PatCredentialProvider implements CredentialProvider<PatCredentialModel>, CredentialInputValidator {

    private static final Logger LOGGER = Logger.getLogger(PatCredentialProvider.class);

    private final KeycloakSession session;

    public PatCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return PatConstants.CREDENTIAL_TYPE;
    }

    /**
     * Only called by realm imports (the REST API stores PATs itself). Refuses, and so fails the import, a PAT
     * without its SHA-256 hash and metadata.
     */
    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, PatCredentialModel credentialModel) {
        if (!PatTokenHasher.isHash(credentialModel.getSecretData()) || credentialModel.getPatCredentialData() == null) {
            throw new IllegalArgumentException("Not a Personal Access Token exported by Keycloak (user "
                + user.getUsername() + "): secretData must hold its SHA-256 hash and credentialData its metadata");
        }
        CredentialModel storedCredential = user.credentialManager().createStoredCredential(credentialModel);
        LOGGER.debugf("PAT imported - User: %s, ID: %s", user.getUsername(), storedCredential.getId());
        return storedCredential;
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        boolean deleted = user.credentialManager().removeStoredCredentialById(credentialId);
        if (deleted) {
            LOGGER.debugf("PAT deleted - User: %s, ID: %s", user.getUsername(), credentialId);
        }
        return deleted;
    }

    @Override
    public PatCredentialModel getCredentialFromModel(CredentialModel model) {
        return PatCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
            .type(PatConstants.CREDENTIAL_TYPE)
            .category(CredentialTypeMetadata.Category.TWO_FACTOR)
            .displayName("Personal Access Token")
            .helpText("Personal access tokens for API authentication")
            .removeable(true)
            .build(session);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PatConstants.CREDENTIAL_TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return user.credentialManager().getStoredCredentialsByTypeStream(PatConstants.CREDENTIAL_TYPE)
            .findAny().isPresent();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        return PatConstants.CREDENTIAL_TYPE.equals(input.getType())
            && findMatchingPat(user, input.getChallengeResponse()).isPresent();
    }

    /**
     * The user's non-expired PAT that the token value belongs to. The token is hashed once and compared with
     * every PAT of the user.
     */
    public Optional<PatCredentialModel> findMatchingPat(UserModel user, String tokenValue) {
        if (tokenValue == null || tokenValue.isEmpty()) {
            return Optional.empty();
        }
        byte[] digest = PatTokenHasher.digest(tokenValue);
        return user.credentialManager().getStoredCredentialsByTypeStream(PatConstants.CREDENTIAL_TYPE)
            .map(this::getCredentialFromModel)
            .filter(pat -> !pat.isExpired() && PatTokenHasher.matches(digest, pat.getSecretData()))
            .findFirst();
    }

    /**
     * Updates the PAT's last-used timestamp. A failure is logged and does not fail the request.
     */
    public void recordUse(UserModel user, PatCredentialModel pat) {
        try {
            SubjectCredentialManager credManager = user.credentialManager();
            // Re-read the stored credential so a concurrent rotation is not overwritten
            CredentialModel model = credManager.getStoredCredentialById(pat.getId());
            if (model == null) {
                return;
            }
            PatCredentialData data = JsonSerialization.readValue(model.getCredentialData(), PatCredentialData.class);
            data.setLastUsedAt(Instant.now());
            model.setCredentialData(JsonSerialization.writeValueAsString(data));
            credManager.updateStoredCredential(model);
        } catch (Exception e) {
            LOGGER.warnf("Failed to record use of PAT %s: %s", pat.getId(), e.getMessage());
        }
    }
}
