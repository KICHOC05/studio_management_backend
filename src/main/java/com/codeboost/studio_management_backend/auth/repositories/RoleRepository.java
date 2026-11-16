package com.codeboost.studio_management_backend.auth.repositories;

import com.codeboost.studio_management_backend.user.models.Role;
import com.codeboost.studio_management_backend.user.enums.RoleCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByCode(RoleCode code);
}
