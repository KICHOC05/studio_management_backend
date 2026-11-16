package com.codeboost.studio_management_backend.security;

import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
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

    public TokenRevocationValidator(RevokedAccessTokenRepository revokedTokens) {
        this.revokedTokens = revokedTokens;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (jwt.getId() == null || jwt.getId().length() != 36 || jwt.getExpiresAt() == null) {
            return invalid();
        }
        try {
            return revokedTokens.existsById(jwt.getId()) ? invalid() : OAuth2TokenValidatorResult.success();
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
