package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.config.RefreshTokenProperties;
import com.codeboost.studio_management_backend.auth.services.RefreshTokenCookieService;
import com.codeboost.studio_management_backend.auth.services.RefreshTokenService.IssuedRefreshToken;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.*;

class RefreshTokenCookieServiceTests {
    private final Instant now = Instant.parse("2026-11-16T12:00:00Z");
    private final RefreshTokenProperties properties = new RefreshTokenProperties();
    private final RefreshTokenCookieService cookies = new RefreshTokenCookieService(properties, Clock.fixed(now, ZoneOffset.UTC));

    @Test
    void usesSecureHttpOnlyHostCookieWithAbsoluteExpiry() {
        var cookie = cookies.issue(new IssuedRefreshToken(1L, "random-refresh", now.plusSeconds(604800)));
        assertTrue(cookie.isHttpOnly());
        assertTrue(cookie.isSecure());
        assertEquals("Strict", cookie.getSameSite());
        assertEquals("/api/auth", cookie.getPath());
        assertNull(cookie.getDomain());
        assertEquals(604800, cookie.getMaxAge().getSeconds());
        assertEquals(600, cookies.issue(new IssuedRefreshToken(1L, "random-refresh", now.plusSeconds(600))).getMaxAge().getSeconds());
    }

    @Test
    void permitsLocalHttpOnlyWhenExplicitlyConfigured() {
        properties.setCookieSecure(false);
        assertFalse(cookies.issue(new IssuedRefreshToken(1L, "token", now.plusSeconds(600))).isSecure());
        assertTrue(cookies.issue(new IssuedRefreshToken(1L, "token", now.plusSeconds(600))).isHttpOnly());
    }

    @Test
    void clearsCookieWithSameScopeAndSecurityAttributes() {
        var cookie = cookies.clear();
        assertEquals("refresh_token", cookie.getName());
        assertEquals("", cookie.getValue());
        assertEquals(0, cookie.getMaxAge().getSeconds());
        assertEquals("/api/auth", cookie.getPath());
        assertTrue(cookie.isSecure());
        assertTrue(cookie.isHttpOnly());
    }
}
