package com.codeboost.studio_management_backend.auth;

import com.codeboost.studio_management_backend.auth.repositories.*;
import com.codeboost.studio_management_backend.auth.services.InitialAdminService;
import com.codeboost.studio_management_backend.user.models.Role;
import com.codeboost.studio_management_backend.user.models.User;
import com.codeboost.studio_management_backend.user.models.UserRole;
import com.codeboost.studio_management_backend.user.enums.RoleCode;
import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class InitialAdminServiceTests {
    private final UserRepository users = mock(UserRepository.class);
    private final RoleRepository roles = mock(RoleRepository.class);
    private final UserRoleRepository assignments = mock(UserRoleRepository.class);
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);

    @Test
    void createsActiveAdminWithHashedPasswordAndRole() {
        when(users.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        Role existingRole = new Role();
        existingRole.setId(1L);
        existingRole.setCode(RoleCode.ADMIN);
        when(roles.findByCode(RoleCode.ADMIN)).thenReturn(Optional.of(existingRole));
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var service = new InitialAdminService(users, roles, assignments, encoder, factory.getValidator());
            service.createIfMissing(" ADMIN@example.com ", "initial-password");
        }
        ArgumentCaptor<User> user = ArgumentCaptor.forClass(User.class);
        verify(users).save(user.capture());
        assertEquals("admin@example.com", user.getValue().getEmailNormalized());
        assertEquals("ACTIVE", user.getValue().getStatus());
        assertTrue(encoder.matches("initial-password", user.getValue().getPasswordHash()));
        ArgumentCaptor<UserRole> assignment = ArgumentCaptor.forClass(UserRole.class);
        verify(assignments).save(assignment.capture());
        assertSame(user.getValue(), assignment.getValue().getUser());
        assertEquals(RoleCode.ADMIN, assignment.getValue().getRole().getCode());
        assertSame(existingRole, assignment.getValue().getRole());
        verify(roles, never()).save(any());
    }

    @Test
    void doesNotDuplicateOrChangeAnExistingAdmin() {
        when(assignments.existsByRole_Code(RoleCode.ADMIN)).thenReturn(true);
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            new InitialAdminService(users, roles, assignments, encoder, factory.getValidator())
                    .createIfMissing("", "");
        }
        verifyNoInteractions(users, roles);
        verify(assignments, never()).save(any());
    }

    @Test
    void requiresAdminRoleFromMigrationBeforeSavingUser() {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var service = new InitialAdminService(users, roles, assignments, encoder, factory.getValidator());
            assertThrows(IllegalStateException.class,
                    () -> service.createIfMissing("admin@example.com", "initial-password"));
        }
        verify(users, never()).save(any());
        verify(roles, never()).save(any());
        verify(assignments, never()).save(any());
    }

    @Test
    void refusesToPromoteAnExistingAccountOrAcceptWeakPassword() {
        when(users.findByEmailNormalized("admin@example.com")).thenReturn(Optional.of(new User()));
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var service = new InitialAdminService(users, roles, assignments, encoder, factory.getValidator());
            assertThrows(IllegalStateException.class, () -> service.createIfMissing("admin@example.com", "initial-password"));
            assertThrows(IllegalStateException.class, () -> service.createIfMissing("admin@example.com", "weak"));
        }
        verify(users, never()).save(any());
        verify(assignments, never()).save(any());
    }
}
