package com.codeboost.studio_management_backend.auth.repositories;

import com.codeboost.studio_management_backend.user.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmailNormalized(String emailNormalized);
    Optional<User> findByPublicId(String publicId);
}
