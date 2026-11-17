package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.config.RefreshTokenProperties;
import com.codeboost.studio_management_backend.auth.models.AuthSession;
import com.codeboost.studio_management_backend.auth.repositories.AuthSessionRepository;
import com.codeboost.studio_management_backend.auth.services.RefreshTokenService;
import com.codeboost.studio_management_backend.user.models.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RefreshTokenServiceTests {
    private final AuthSessionRepository sessions = mock(AuthSessionRepository.class);
    private final Instant now = Instant.parse("2026-11-16T12:00:00Z");
    private final RefreshTokenProperties properties = new RefreshTokenProperties();
    private final RefreshTokenService service = new RefreshTokenService(sessions, properties, Clock.fixed(now, ZoneOffset.UTC));

    @BeforeEach
    void persistIds() {
        var ids = new java.util.concurrent.atomic.AtomicLong();
        when(sessions.save(any(AuthSession.class))).thenAnswer(invocation -> {
            AuthSession session = invocation.getArgument(0);
            session.setId(ids.incrementAndGet());
            return session;
        });
    }

    @Test
    void storesOnlySha256HashAndSevenDayAbsoluteExpiry() throws Exception {
        User user = new User();
        var issued = service.issueForLogin(user);
        var saved = ArgumentCaptor.forClass(AuthSession.class);
        verify(sessions).save(saved.capture());
        var session = saved.getValue();
        assertSame(user, session.getUser());
        assertEquals(session.getId(), issued.sessionId());
        assertEquals(32, Base64.getUrlDecoder().decode(issued.token()).length);
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(issued.token().getBytes(StandardCharsets.US_ASCII))), session.getRefreshTokenHash());
        assertEquals(64, session.getRefreshTokenHash().length());
        assertNotEquals(issued.token(), session.getRefreshTokenHash());
        assertEquals(now.plusSeconds(7 * 86400), issued.expiresAt());
        assertEquals(LocalDateTime.ofInstant(issued.expiresAt(), ZoneOffset.UTC), session.getExpiresAt());
        assertNull(session.getRevokedAt());
        assertFalse(issued.toString().contains(issued.token()));
    }

    @Test
    void eachLoginCreatesDistinctTokenAndSessionWithoutChangingPreviousExpiry() {
        User user = new User();
        var first = service.issueForLogin(user);
        var later = new RefreshTokenService(sessions, properties,
                Clock.fixed(now.plusSeconds(3600), ZoneOffset.UTC)).issueForLogin(user);
        var saved = ArgumentCaptor.forClass(AuthSession.class);
        verify(sessions, times(2)).save(saved.capture());
        assertNotEquals(first.token(), later.token());
        assertNotEquals(first.sessionId(), later.sessionId());
        assertNotSame(saved.getAllValues().get(0), saved.getAllValues().get(1));
        assertNotEquals(saved.getAllValues().get(0).getRefreshTokenHash(), saved.getAllValues().get(1).getRefreshTokenHash());
        assertEquals(LocalDateTime.ofInstant(now.plusSeconds(7 * 86400), ZoneOffset.UTC),
                saved.getAllValues().get(0).getExpiresAt());
    }

    @Test
    void supportsConfiguredLifetimeForNewSessions() {
        properties.setLifetimeDays(3);
        assertEquals(now.plusSeconds(3 * 86400), service.issueForLogin(new User()).expiresAt());
    }
}
