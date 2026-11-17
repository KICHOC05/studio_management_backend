package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
import com.codeboost.studio_management_backend.auth.repositories.AuthSessionRepository;
import com.codeboost.studio_management_backend.auth.repositories.ConsumedRefreshTokenRepository;
import java.time.Clock;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Isolation;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class LogoutService {
    private final RevokedAccessTokenRepository revokedTokens;
    private final AuthSessionRepository sessions;
    private final Clock clock;
    private final ConsumedRefreshTokenRepository consumed;

    public LogoutService(RevokedAccessTokenRepository revokedTokens, AuthSessionRepository sessions,
                          ConsumedRefreshTokenRepository consumed, Clock clock) {
        this.revokedTokens = revokedTokens;
        this.sessions = sessions;
        this.clock = clock;
        this.consumed = consumed;
    }

    @Transactional
    @PreAuthorize("isAuthenticated() and #jwt.subject == authentication.name")
    public void logout(Jwt jwt) {
        revokedTokens.revoke(jwt.getId(), LocalDateTime.ofInstant(jwt.getExpiresAt(), ZoneOffset.UTC));
        sessions.revokeForUser(Long.parseLong(jwt.getClaimAsString("sid")), jwt.getSubject(),
                LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
    }

    /** Possession of a current or consumed refresh authorizes revoking only its own session. */
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void logoutByRefresh(String rawToken) {
        if (rawToken == null || !rawToken.matches("[A-Za-z0-9_-]{43}")) {
            throw new RefreshTokenRejectedException();
        }
        String hash = RefreshTokenService.hash(rawToken);
        Long sessionId = sessions.findSessionIdByRefreshTokenHash(hash)
                .or(() -> consumed.findSessionIdByHash(hash))
                .orElseThrow(RefreshTokenRejectedException::new);
        var session = sessions.findLockedById(sessionId).orElseThrow(RefreshTokenRejectedException::new);
        if (!hash.equals(session.getRefreshTokenHash()) && !consumed.existsById(hash)) {
            throw new RefreshTokenRejectedException();
        }
        // Idempotent even for an already revoked, expired or inactive session.
        if (session.getRevokedAt() == null) {
            session.setRevokedAt(LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
        }
    }
}
