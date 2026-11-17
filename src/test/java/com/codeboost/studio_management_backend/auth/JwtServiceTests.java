package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.dto.AuthenticatedUser;
import com.codeboost.studio_management_backend.auth.services.JwtService;
import com.codeboost.studio_management_backend.security.JwtConfig;
import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
import com.codeboost.studio_management_backend.auth.repositories.AuthSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtServiceTests {
    private final JwtConfig config = new JwtConfig();
    private final SecretKey key = config.jwtSigningKey(Base64.getEncoder().encodeToString(new byte[32]));
    private final JwtEncoder encoder = config.jwtEncoder(key);
    private final RevokedAccessTokenRepository revokedTokens = mock(RevokedAccessTokenRepository.class);
    private final AuthSessionRepository sessions = mock(AuthSessionRepository.class);
    private final JwtDecoder decoder = config.jwtDecoder(key, "test-issuer", revokedTokens, sessions, Clock.systemUTC());

    @BeforeEach
    void activeSession() {
        when(sessions.existsByIdAndUser_PublicIdAndUser_StatusAndRevokedAtIsNullAndExpiresAtAfter(
                eq(1L), anyString(), eq("ACTIVE"), any())).thenReturn(true);
    }

    @Test
    void issuesSignedTokenWithPublicIdRolesAndExpiration() {
        var service = new JwtService(encoder, Clock.systemUTC(), "test-issuer", 15);
        var response = service.issueToken(new AuthenticatedUser("user-public-id", "admin@example.com", List.of("ADMIN")), 1L);
        Jwt jwt = decoder.decode(response.accessToken());
        assertEquals("user-public-id", jwt.getSubject());
        assertEquals("1", jwt.getClaimAsString("sid"));
        assertEquals(List.of("ADMIN"), jwt.getClaimAsStringList("roles"));
        assertEquals(900, response.expiresIn());
        assertEquals(900, jwt.getExpiresAt().getEpochSecond() - jwt.getIssuedAt().getEpochSecond());
        assertFalse(jwt.hasClaim("password"));
        assertFalse(jwt.hasClaim("password_hash"));
    }

    @Test
    void rejectsExpiredTokens() {
        assertThrows(JwtException.class, () -> decoder.decode(token("test-issuer", "studio-management-api", Instant.now().minusSeconds(120))));
    }

    @Test
    void rejectsWrongIssuerAndAudience() {
        assertThrows(JwtException.class, () -> decoder.decode(token("wrong", "studio-management-api", Instant.now().plusSeconds(300))));
        assertThrows(JwtException.class, () -> decoder.decode(token("test-issuer", "wrong", Instant.now().plusSeconds(300))));
    }

    @Test
    void rejectsDifferentSigningKey() {
        byte[] otherBytes = new byte[32];
        otherBytes[0] = 1;
        JwtDecoder otherDecoder = config.jwtDecoder(config.jwtSigningKey(Base64.getEncoder().encodeToString(otherBytes)), "test-issuer", revokedTokens, sessions, Clock.systemUTC());
        assertThrows(JwtException.class, () -> otherDecoder.decode(token("test-issuer", "studio-management-api", Instant.now().plusSeconds(300))));
    }

    @Test
    void rejectsMissingOrWeakSecret() {
        assertThrows(IllegalStateException.class, () -> config.jwtSigningKey(""));
        assertThrows(IllegalStateException.class, () -> config.jwtSigningKey("not-base64!"));
    }

    @Test
    void rejectsRevokedTokenIncludingAfterDecoderRecreation() {
        var response = new JwtService(encoder, Clock.systemUTC(), "test-issuer", 15)
                .issueToken(new AuthenticatedUser("public-id", "user@example.com", List.of("USER")), 1L);
        String id = decoder.decode(response.accessToken()).getId();
        when(revokedTokens.existsById(id)).thenReturn(true);
        assertThrows(JwtException.class, () -> decoder.decode(response.accessToken()));
        JwtDecoder restartedDecoder = config.jwtDecoder(key, "test-issuer", revokedTokens, sessions, Clock.systemUTC());
        assertThrows(JwtException.class, () -> restartedDecoder.decode(response.accessToken()));
    }

    @Test
    void rejectsAccessWhenRevocationStorageIsUnavailable() {
        String token = token("test-issuer", "studio-management-api", Instant.now().plusSeconds(300));
        when(revokedTokens.existsById(anyString()))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("Database unavailable"));
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    private String token(String issuer, String audience, Instant expiresAt) {
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),
                JwtClaimsSet.builder().issuer(issuer).subject("public-id")
                        .id(java.util.UUID.randomUUID().toString())
                        .claim("sid", "1")
                        .audience(List.of(audience)).expiresAt(expiresAt).build())).getTokenValue();
    }

    @Test
    void rejectsMissingRevokedExpiredOrWrongOwnerSession() {
        String token = token("test-issuer", "studio-management-api", Instant.now().plusSeconds(300));
        when(sessions.existsByIdAndUser_PublicIdAndUser_StatusAndRevokedAtIsNullAndExpiresAtAfter(
                eq(1L), eq("public-id"), eq("ACTIVE"), any())).thenReturn(false);
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void rejectsLegacyTokenWithoutSessionReference() {
        String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),
                JwtClaimsSet.builder().issuer("test-issuer").subject("public-id")
                        .id(java.util.UUID.randomUUID().toString()).audience(List.of("studio-management-api"))
                        .expiresAt(Instant.now().plusSeconds(300)).build())).getTokenValue();
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }
}
