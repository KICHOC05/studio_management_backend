package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class LogoutService {
    private final RevokedAccessTokenRepository revokedTokens;

    public LogoutService(RevokedAccessTokenRepository revokedTokens) {
        this.revokedTokens = revokedTokens;
    }

    @Transactional
    @PreAuthorize("isAuthenticated() and #jwt.subject == authentication.name")
    public void logout(Jwt jwt) {
        revokedTokens.revoke(jwt.getId(), LocalDateTime.ofInstant(jwt.getExpiresAt(), ZoneOffset.UTC));
    }
}
