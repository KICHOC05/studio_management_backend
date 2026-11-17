package com.codeboost.studio_management_backend.auth.repositories;

import com.codeboost.studio_management_backend.auth.models.AuthSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;

public interface AuthSessionRepository extends JpaRepository<AuthSession, Long> {
    @Query("select s.id from AuthSession s where s.refreshTokenHash = :hash")
    Optional<Long> findSessionIdByRefreshTokenHash(String hash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from AuthSession s where s.id = :id")
    Optional<AuthSession> findLockedById(Long id);

    boolean existsByIdAndUser_PublicIdAndUser_StatusAndRevokedAtIsNullAndExpiresAtAfter(
            Long id, String publicId, String status, LocalDateTime now);

    @Modifying
    @Query("update AuthSession s set s.revokedAt = :now where s.id = :id "
            + "and s.user.id in (select u.id from User u where u.publicId = :publicId) and s.revokedAt is null")
    int revokeForUser(Long id, String publicId, LocalDateTime now);
}
