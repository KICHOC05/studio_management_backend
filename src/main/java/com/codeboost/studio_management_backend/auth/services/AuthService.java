package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.dto.AuthenticatedUser;
import com.codeboost.studio_management_backend.auth.dto.LoginRequest;
import com.codeboost.studio_management_backend.auth.dto.LoginResponse;
import com.codeboost.studio_management_backend.auth.dto.LoginResult;
import com.codeboost.studio_management_backend.auth.repositories.UserRepository;
import com.codeboost.studio_management_backend.auth.repositories.UserRoleRepository;
import com.codeboost.studio_management_backend.user.models.User;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

@Service
@Transactional(readOnly = true)
public class AuthService {
    private final UserRepository users;
    private final UserRoleRepository userRoles;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final String dummyPasswordHash;

    public AuthService(UserRepository users, UserRoleRepository userRoles,
                       PasswordEncoder passwordEncoder, JwtService jwtService,
                       RefreshTokenService refreshTokenService) {
        this.users = users;
        this.userRoles = userRoles;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.dummyPasswordHash = passwordEncoder.encode(java.util.UUID.randomUUID().toString());
    }

    @Transactional
    public LoginResult login(LoginRequest request) {
        if (request.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new BadCredentialsException("Credenciales invalidas");
        }
        User user = users.findByEmailNormalized(normalizeEmail(request.email())).orElse(null);
        // Check a hash even for unknown accounts, keeping the failure response identical.
        boolean validPassword = passwordEncoder.matches(request.password(),
                user == null ? dummyPasswordHash : user.getPasswordHash());
        if (user == null || !validPassword || !"ACTIVE".equals(user.getStatus())) {
            throw new BadCredentialsException("Credenciales invalidas");
        }
        var refreshToken = refreshTokenService.issueForLogin(user);
        LoginResponse response = jwtService.issueToken(toAuthenticatedUser(user), refreshToken.sessionId());
        return new LoginResult(response, refreshToken);
    }

    @PreAuthorize("#publicId == authentication.name or hasRole('ADMIN')")
    public AuthenticatedUser currentUser(String publicId) {
        User user = users.findByPublicId(publicId)
                .filter(candidate -> "ACTIVE".equals(candidate.getStatus()))
                .orElseThrow(() -> new BadCredentialsException("Credenciales invalidas"));
        return toAuthenticatedUser(user);
    }

    private AuthenticatedUser toAuthenticatedUser(User user) {
        return new AuthenticatedUser(user.getPublicId(), user.getEmailNormalized(),
                userRoles.findRoleCodesByUserId(user.getId()).stream().map(Enum::name).toList());
    }

    public static String normalizeEmail(String email) {
        return email.strip().toLowerCase(Locale.ROOT);
    }
}
