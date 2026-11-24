package com.cloudiam.keycloak.pat.config;

/**
 * Personal Access Token constants.
 */
public final class PatConstants {

    private PatConstants() {
    }

    public static final String CREDENTIAL_TYPE = "pat";

    /** Token format: pat_<base64url(userId)>.<base64url(32 random bytes)> */
    public static final String TOKEN_PREFIX = "pat_";
    public static final char TOKEN_SEPARATOR = '.';
    public static final int TOKEN_RANDOM_BYTES = 32;

    public static final int DEFAULT_EXPIRATION_DAYS = 90;
    public static final int MAX_EXPIRATION_DAYS = 365;
    public static final int MAX_NAME_LENGTH = 255;
    public static final int MAX_PATS_PER_USER = 25;
    public static final int MAX_ROLES_PER_PAT = 50;

    public static final String GRANT_TYPE = "urn:cloudiam:params:oauth:grant-type:pat";

    /** Claims added to tokens obtained with a PAT, also used as event details */
    public static final String CLAIM_GRANT_TYPE = "grant_type";
    public static final String CLAIM_PAT_ID = "pat_id";
    public static final String CLAIM_PAT_NAME = "pat_name";
    public static final String CLAIM_PAT_ROLES = "pat_roles";

    /** Scope a token needs to call the PAT API. Optional scope of admin-cli by default. */
    public static final String PAT_MANAGEMENT_SCOPE = "pat-management";

    /** Scope marking the clients that accept the PAT grant. Assigned to no client by default. */
    public static final String PAT_EXCHANGE_SCOPE = "pat-exchange";

    public static final String PAT_EXCHANGE_SCOPE_DESCRIPTION =
        "Marks the client as accepting Personal Access Tokens (PAT grant type)";
    public static final String PAT_MANAGEMENT_SCOPE_DESCRIPTION =
        "Allows the client to create, list, rotate and delete the user's Personal Access Tokens";
}
