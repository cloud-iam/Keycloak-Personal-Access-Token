package com.cloudiam.keycloak.pat.guard;

import com.cloudiam.keycloak.pat.config.PatConstants;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Refuses grants fed a token obtained with a PAT. Token exchange and UMA rebuild the roles from the user, so they
 * would turn such a token into one without the PAT's limits.
 */
final class PatTokenGuard {

    /** Splits header and parameter values into candidate tokens: "Bearer <jwt>", comma-joined values... */
    private static final Pattern SEPARATORS = Pattern.compile("[\\s,]+");

    private PatTokenGuard() {
    }

    /**
     * @throws CorsErrorResponseException if any Authorization header or form parameter holds a PAT token. Every value
     * is checked, whatever its position: Keycloak reads the first header, which may differ from a joined view of them.
     */
    static void refusePatTokens(OAuth2GrantType.Context context) {
        List<String> authorizations = context.getHeaders().getRequestHeaders().get(HttpHeaders.AUTHORIZATION);
        Stream<String> values = Stream.concat(
            authorizations != null ? authorizations.stream() : Stream.empty(),
            context.getFormParams().values().stream().flatMap(List::stream));

        if (values.filter(Objects::nonNull).flatMap(SEPARATORS::splitAsStream).anyMatch(PatTokenGuard::isPatToken)) {
            String errorMessage = "Tokens obtained with a Personal Access Token cannot be used with this grant";
            context.getEvent().detail(Details.REASON, errorMessage);
            context.getEvent().error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(context.getCors(), OAuthErrorException.INVALID_REQUEST, errorMessage,
                Response.Status.BAD_REQUEST);
        }
    }

    /** Whether the value is a JWT carrying a pat_id claim. The signature is not checked: this only refuses. */
    static boolean isPatToken(String value) {
        if (value == null) {
            return false;
        }
        String[] parts = value.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode claims = JsonSerialization.mapper.readTree(new String(payload, StandardCharsets.UTF_8));
            return claims != null && claims.has(PatConstants.CLAIM_PAT_ID);
        } catch (IOException | IllegalArgumentException e) {
            return false;
        }
    }
}
