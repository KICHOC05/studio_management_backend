package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.config.RefreshTokenProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;

@Component
public class RefreshTokenCookieService {
    private final RefreshTokenProperties properties;
    private final Clock clock;

    public RefreshTokenCookieService(RefreshTokenProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public ResponseCookie issue(RefreshTokenService.IssuedRefreshToken token) {
        long seconds = Math.max(0, Duration.between(clock.instant(), token.expiresAt()).getSeconds());
        return cookie(token.token(), seconds);
    }

    public ResponseCookie clear() {
        return cookie("", 0);
    }

    private ResponseCookie cookie(String value, long seconds) {
        return ResponseCookie.from("refresh_token", value)
                .httpOnly(true).secure(properties.isCookieSecure())
                .sameSite("Strict").path("/api/auth").maxAge(seconds).build();
    }
}
