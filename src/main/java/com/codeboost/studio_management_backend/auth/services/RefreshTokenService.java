package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.config.RefreshTokenProperties;
import com.codeboost.studio_management_backend.auth.models.AuthSession;
import com.codeboost.studio_management_backend.auth.repositories.AuthSessionRepository;
import com.codeboost.studio_management_backend.user.models.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class RefreshTokenService {
    private final AuthSessionRepository sessions;
    private final RefreshTokenProperties properties;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public RefreshTokenService(AuthSessionRepository sessions, RefreshTokenProperties properties, Clock clock) {
        this.sessions = sessions;
        this.properties = properties;
        this.clock = clock;
    }

    /** Creates a new independent session. This operation is for login, not rotation. */
    @Transactional
    public IssuedRefreshToken issueForLogin(User user) {
        String token = newToken();
        Instant expiresAt = clock.instant().plus(properties.getLifetimeDays(), ChronoUnit.DAYS)
                .truncatedTo(ChronoUnit.MICROS);
        AuthSession session = new AuthSession();
        session.setUser(user);
        session.setRefreshTokenHash(hash(token));
        session.setExpiresAt(LocalDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
        session = sessions.save(session);
        return new IssuedRefreshToken(session.getId(), token, expiresAt);
    }

    String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 no disponible", ex);
        }
    }

    /** Raw token lives only in memory for delivery to the client; never log it. */
    public record IssuedRefreshToken(Long sessionId, String token, Instant expiresAt) {
        @Override
        public String toString() {
            return "IssuedRefreshToken[token=REDACTED]";
        }
    }
}
