package com.cloudiam.keycloak.pat.credentials;

import com.cloudiam.keycloak.pat.models.PatCredentialData;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

/**
 * Typed access to a PAT credential's metadata.
 */
public class PatCredentialModel extends CredentialModel {

    private PatCredentialModel(CredentialModel credentialModel) {
        super.setId(credentialModel.getId());
        super.setType(credentialModel.getType());
        super.setUserLabel(credentialModel.getUserLabel());
        super.setCreatedDate(credentialModel.getCreatedDate());
        super.setSecretData(credentialModel.getSecretData());
        super.setCredentialData(credentialModel.getCredentialData());
    }

    public static PatCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        return new PatCredentialModel(credentialModel);
    }

    /** The metadata, or null if there is none. */
    public PatCredentialData getPatCredentialData() {
        String data = getCredentialData();
        if (data == null || data.isEmpty()) {
            return null;
        }
        try {
            return JsonSerialization.readValue(data, PatCredentialData.class);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to deserialize PAT credential data", e);
        }
    }

    public boolean isExpired() {
        return getPatCredentialData().isExpired();
    }

    public String getName() {
        return getPatCredentialData().getName();
    }
}
