package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
import com.codeboost.studio_management_backend.auth.services.RevokedTokenCleanup;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static org.mockito.Mockito.*;

class RevokedTokenCleanupTests {
    @Test
    void keepsRevocationsBeyondClockSkew() {
        var repository = mock(RevokedAccessTokenRepository.class);
        Instant now = Instant.parse("2026-11-13T12:00:00Z");
        new RevokedTokenCleanup(repository, Clock.fixed(now, ZoneOffset.UTC)).deleteExpired();
        verify(repository).deleteExpired(LocalDateTime.ofInstant(now.minusSeconds(300), ZoneOffset.UTC));
    }
}
