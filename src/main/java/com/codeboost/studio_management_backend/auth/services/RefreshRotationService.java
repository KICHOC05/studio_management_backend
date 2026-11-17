package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.dto.AuthenticatedUser;
import com.codeboost.studio_management_backend.auth.dto.LoginResult;
import com.codeboost.studio_management_backend.auth.models.ConsumedRefreshToken;
import com.codeboost.studio_management_backend.auth.repositories.AuthSessionRepository;
import com.codeboost.studio_management_backend.auth.repositories.ConsumedRefreshTokenRepository;
import com.codeboost.studio_management_backend.auth.repositories.UserRoleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class RefreshRotationService {
    private final AuthSessionRepository sessions;
    private final ConsumedRefreshTokenRepository consumed;
    private final UserRoleRepository roles;
    private final RefreshTokenService tokens;
    private final JwtService jwt;
    private final Clock clock;

    public RefreshRotationService(AuthSessionRepository sessions, ConsumedRefreshTokenRepository consumed,
                                  UserRoleRepository roles, RefreshTokenService tokens, JwtService jwt, Clock clock) {
        this.sessions = sessions;
        this.consumed = consumed;
        this.roles = roles;
        this.tokens = tokens;
        this.jwt = jwt;
        this.clock = clock;
    }

    // READ_COMMITTED lets a request waiting for the lock see the previous rotation's history.
    // All infrastructure/signing failures still roll back hash changes and history inserts.
    @Transactional(isolation = Isolation.READ_COMMITTED, noRollbackFor = RefreshTokenRejectedException.class)
    public LoginResult refresh(String rawToken) {
        if (rawToken == null || !rawToken.matches("[A-Za-z0-9_-]{43}")) {
            throw new RefreshTokenRejectedException();
        }
        String oldHash = RefreshTokenService.hash(rawToken);
        Long sessionId = sessions.findSessionIdByRefreshTokenHash(oldHash)
                .or(() -> consumed.findSessionIdByHash(oldHash))
                .orElseThrow(RefreshTokenRejectedException::new);
        var session = sessions.findLockedById(sessionId).orElseThrow(RefreshTokenRejectedException::new);
        LocalDateTime now = LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        if (!oldHash.equals(session.getRefreshTokenHash())) {
            if (consumed.existsById(oldHash) && session.getRevokedAt() == null) {
                session.setRevokedAt(now);
            }
            throw new RefreshTokenRejectedException();
        }
        if (session.getRevokedAt() != null || !session.getExpiresAt().isAfter(now)) {
            throw new RefreshTokenRejectedException();
        }
        var user = session.getUser();
        if (!"ACTIVE".equals(user.getStatus())) {
            session.setRevokedAt(now);
            throw new RefreshTokenRejectedException();
        }
        var identity = new AuthenticatedUser(user.getPublicId(), user.getEmailNormalized(),
                roles.findRoleCodesByUserId(user.getId()).stream().map(Enum::name).toList());
        var access = jwt.issueToken(identity, sessionId);
        String replacement = tokens.newToken();
        consumed.save(new ConsumedRefreshToken(oldHash, session, now));
        session.setRefreshTokenHash(RefreshTokenService.hash(replacement));
        return new LoginResult(access, new RefreshTokenService.IssuedRefreshToken(sessionId, replacement,
                session.getExpiresAt().toInstant(ZoneOffset.UTC)));
    }
}
