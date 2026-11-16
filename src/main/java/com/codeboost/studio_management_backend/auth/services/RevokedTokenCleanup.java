package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Component
public class RevokedTokenCleanup {
    private final RevokedAccessTokenRepository tokens;
    private final Clock clock;

    public RevokedTokenCleanup(RevokedAccessTokenRepository tokens, Clock clock) {
        this.tokens = tokens;
        this.clock = clock;
    }

    @Scheduled(fixedDelay = 3600000, initialDelay = 3600000)
    @Transactional
    public void deleteExpired() {
        // Keep entries beyond Spring Security's default timestamp clock skew (60 seconds).
        tokens.deleteExpired(LocalDateTime.ofInstant(clock.instant().minusSeconds(300), ZoneOffset.UTC));
    }
}
