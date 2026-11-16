package com.codeboost.studio_management_backend.auth.services;

import com.codeboost.studio_management_backend.auth.dto.LoginRequest;
import com.codeboost.studio_management_backend.auth.repositories.RoleRepository;
import com.codeboost.studio_management_backend.auth.repositories.UserRepository;
import com.codeboost.studio_management_backend.auth.repositories.UserRoleRepository;
import com.codeboost.studio_management_backend.user.models.Role;
import com.codeboost.studio_management_backend.user.models.User;
import com.codeboost.studio_management_backend.user.models.UserRole;
import com.codeboost.studio_management_backend.user.enums.RoleCode;
import jakarta.validation.Validator;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;

@Service
public class InitialAdminService {
    private final UserRepository users;
    private final RoleRepository roles;
    private final UserRoleRepository userRoles;
    private final PasswordEncoder encoder;
    private final Validator validator;

    public InitialAdminService(UserRepository users, RoleRepository roles, UserRoleRepository userRoles,
                               PasswordEncoder encoder, Validator validator) {
        this.users = users;
        this.roles = roles;
        this.userRoles = userRoles;
        this.encoder = encoder;
        this.validator = validator;
    }

    @Transactional
    public void createIfMissing(String email, String password) {
        // Bootstrap only the first administrator. Never reset passwords or promote existing accounts.
        if (userRoles.existsByRole_Code(RoleCode.ADMIN)) {
            return;
        }
        String normalizedEmail = AuthService.normalizeEmail(email);
        if (!validator.validate(new LoginRequest(normalizedEmail, password)).isEmpty()
                || password.length() < 12 || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalStateException(
                    "Configura INITIAL_ADMIN_EMAIL y una INITIAL_ADMIN_PASSWORD de al menos 12 caracteres y maximo 72 bytes UTF-8.");
        }
        if (users.findByEmailNormalized(normalizedEmail).isPresent()) {
            throw new IllegalStateException("El correo del admin inicial ya pertenece a una cuenta. No se modificara.");
        }
        Role role = roles.findByCode(RoleCode.ADMIN).orElseThrow(() ->
                new IllegalStateException("El rol ADMIN no existe. Aplica la migracion V2 de Flyway."));
        User admin = new User();
        admin.setEmailNormalized(normalizedEmail);
        admin.setPasswordHash(encoder.encode(password));
        admin.setStatus("ACTIVE");
        admin = users.save(admin);

        UserRole assignment = new UserRole();
        assignment.setUser(admin);
        assignment.setRole(role);
        userRoles.save(assignment);
    }
}
