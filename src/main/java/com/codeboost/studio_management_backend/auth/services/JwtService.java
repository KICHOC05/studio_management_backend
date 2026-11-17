package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.dto.AuthenticatedUser;
import com.codeboost.studio_management_backend.auth.dto.LoginResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
public class JwtService {
    private final JwtEncoder encoder;
    private final Clock clock;
    private final String issuer;
    private final long accessTokenMinutes;

    public JwtService(JwtEncoder encoder, Clock clock,
                      @Value("${app.jwt.issuer}") String issuer,
                      @Value("${app.jwt.access-token-minutes}") long accessTokenMinutes) {
        if (accessTokenMinutes < 1 || accessTokenMinutes > 60) {
            throw new IllegalArgumentException("JWT_ACCESS_TOKEN_MINUTES debe estar entre 1 y 60.");
        }
        this.encoder = encoder;
        this.clock = clock;
        this.issuer = issuer;
        this.accessTokenMinutes = accessTokenMinutes;
    }

    public LoginResponse issueToken(AuthenticatedUser user, Long sessionId) {
        if (sessionId == null || sessionId <= 0) {
            throw new IllegalArgumentException("El JWT requiere una sesion persistida.");
        }
        Instant now = clock.instant();
        long expiresIn = accessTokenMinutes * 60;
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(user.publicId())
                .audience(java.util.List.of("studio-management-api"))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresIn))
                .id(UUID.randomUUID().toString())
                .claim("roles", user.roles())
                .claim("sid", sessionId.toString())
                .build();
        String token = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        return new LoginResponse(token, "Bearer", expiresIn, user);
    }
}
