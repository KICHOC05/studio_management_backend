package com.codeboost.studio_management_backend.auth.repositories;

import com.codeboost.studio_management_backend.user.models.UserRole;
import com.codeboost.studio_management_backend.user.models.UserRoleId;
import com.codeboost.studio_management_backend.user.enums.RoleCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRole, UserRoleId> {
    @Query("select ur.role.code from UserRole ur where ur.user.id = :userId order by ur.role.code")
    List<RoleCode> findRoleCodesByUserId(Long userId);

    boolean existsByRole_Code(RoleCode code);
}
