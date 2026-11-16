package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.dto.AuthenticatedUser;
import com.codeboost.studio_management_backend.auth.dto.LoginRequest;
import com.codeboost.studio_management_backend.auth.dto.LoginResponse;
import com.codeboost.studio_management_backend.auth.repositories.UserRepository;
import com.codeboost.studio_management_backend.auth.repositories.UserRoleRepository;
import com.codeboost.studio_management_backend.auth.services.AuthService;
import com.codeboost.studio_management_backend.auth.services.JwtService;
import com.codeboost.studio_management_backend.user.models.User;
import com.codeboost.studio_management_backend.user.enums.RoleCode;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceTests {
    private final UserRepository users = mock(UserRepository.class);
    private final UserRoleRepository roles = mock(UserRoleRepository.class);
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final JwtService jwt = mock(JwtService.class);
    private final AuthService service = new AuthService(users, roles, encoder, jwt);

    @Test
    void authenticatesNormalizedEmailAndReturnsOnlyPublicIdentity() {
        User user = activeUser();
        when(users.findByEmailNormalized("admin@example.com")).thenReturn(Optional.of(user));
        when(roles.findRoleCodesByUserId(1L)).thenReturn(List.of(RoleCode.ADMIN));
        AuthenticatedUser identity = new AuthenticatedUser("public-id", "admin@example.com", List.of("ADMIN"));
        when(jwt.issueToken(identity)).thenReturn(new LoginResponse("token", "Bearer", 900, identity));

        var result = service.login(new LoginRequest(" ADMIN@EXAMPLE.COM ", "long-password"));
        assertEquals("token", result.accessToken());
        assertEquals(identity, result.user());
    }

    @Test
    void rejectsWrongPasswordUnknownEmailAndInactiveUser() {
        User user = activeUser();
        when(users.findByEmailNormalized("admin@example.com")).thenReturn(Optional.of(user));
        assertThrows(BadCredentialsException.class, () -> service.login(new LoginRequest("admin@example.com", "wrong")));
        assertThrows(BadCredentialsException.class, () -> service.login(new LoginRequest("unknown@example.com", "long-password")));
        user.setStatus("INACTIVE");
        assertThrows(BadCredentialsException.class, () -> service.login(new LoginRequest("admin@example.com", "long-password")));
        verifyNoInteractions(jwt);
    }

    @Test
    void rejectsPasswordsOverBcryptByteLimit() {
        assertThrows(BadCredentialsException.class,
                () -> service.login(new LoginRequest("admin@example.com", "ñ".repeat(40))));
        verifyNoInteractions(jwt);
    }

    private User activeUser() {
        User user = new User();
        user.setId(1L);
        user.setPublicId("public-id");
        user.setEmailNormalized("admin@example.com");
        user.setPasswordHash(encoder.encode("long-password"));
        user.setStatus("ACTIVE");
        return user;
    }
}
