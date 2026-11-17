package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.repositories.UserRepository;
import com.codeboost.studio_management_backend.auth.repositories.UserRoleRepository;
import com.codeboost.studio_management_backend.auth.services.AuthService;
import com.codeboost.studio_management_backend.auth.services.JwtService;
import com.codeboost.studio_management_backend.auth.services.RefreshTokenService;
import com.codeboost.studio_management_backend.user.models.User;
import com.codeboost.studio_management_backend.user.enums.RoleCode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringJUnitConfig(AuthAuthorizationTests.Config.class)
class AuthAuthorizationTests {
    @Autowired
    private AuthService auth;

    @Test
    @WithMockUser(username = "alice")
    void userCannotReadAnotherIdentity() {
        assertThrows(AccessDeniedException.class, () -> auth.currentUser("bob"));
    }

    @Test
    @WithMockUser(username = "alice")
    void userCanReadOwnIdentity() {
        assertEquals("alice", auth.currentUser("alice").publicId());
    }

    @Test
    @WithMockUser(username = "administrator", roles = "ADMIN")
    void administratorCanReadIdentity() {
        assertEquals("alice", auth.currentUser("alice").publicId());
    }

    @Configuration
    @EnableMethodSecurity
    static class Config {
        @Bean
        AuthService authService() {
            var users = mock(UserRepository.class);
            var roles = mock(UserRoleRepository.class);
            var alice = new User();
            alice.setId(1L);
            alice.setPublicId("alice");
            alice.setStatus("ACTIVE");
            when(users.findByPublicId("alice")).thenReturn(Optional.of(alice));
            when(roles.findRoleCodesByUserId(1L)).thenReturn(List.of(RoleCode.CLIENT));
            return new AuthService(users, roles, new BCryptPasswordEncoder(4), mock(JwtService.class), mock(RefreshTokenService.class));
        }
    }
}
