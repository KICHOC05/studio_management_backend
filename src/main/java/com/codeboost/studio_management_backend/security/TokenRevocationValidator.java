package com.codeboost.studio_management_backend.security;

import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
import com.codeboost.studio_management_backend.auth.repositories.AuthSessionRepository;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class TokenRevocationValidator implements OAuth2TokenValidator<Jwt> {
    private static final Logger log = LoggerFactory.getLogger(TokenRevocationValidator.class);
    private final RevokedAccessTokenRepository revokedTokens;
    private final AuthSessionRepository sessions;
    private final Clock clock;

    public TokenRevocationValidator(RevokedAccessTokenRepository revokedTokens, AuthSessionRepository sessions, Clock clock) {
        this.revokedTokens = revokedTokens;
        this.sessions = sessions;
        this.clock = clock;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (jwt.getId() == null || jwt.getId().length() != 36 || jwt.getExpiresAt() == null) {
            return invalid();
        }
        try {
            Object sidClaim = jwt.getClaims().get("sid");
            if (!(sidClaim instanceof String sid) || sid.length() > 19 || !sid.matches("[1-9][0-9]*")) {
                return invalid();
            }
            long sessionId;
            try {
                sessionId = Long.parseLong(sid);
            } catch (NumberFormatException ex) {
                return invalid();
            }
            boolean active = !revokedTokens.existsById(jwt.getId())
                    && sessions.existsByIdAndUser_PublicIdAndUser_StatusAndRevokedAtIsNullAndExpiresAtAfter(
                            sessionId, jwt.getSubject(), "ACTIVE", LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
            return active ? OAuth2TokenValidatorResult.success() : invalid();
        } catch (DataAccessException ex) {
            // Never accept a token when revocation cannot be checked.
            log.error("No se pudo consultar la revocacion de tokens", ex);
            return invalid();
        }
    }

    private OAuth2TokenValidatorResult invalid() {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Token no valido", null));
    }
}
