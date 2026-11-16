package com.codeboost.studio_management_backend.auth.repositories;

import com.codeboost.studio_management_backend.auth.models.RevokedAccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDateTime;

public interface RevokedAccessTokenRepository extends JpaRepository<RevokedAccessToken, String> {
    @Modifying
    @Query(value = "INSERT INTO revoked_access_tokens (token_id, expires_at) VALUES (:tokenId, :expiresAt) "
            + "ON DUPLICATE KEY UPDATE token_id = token_id", nativeQuery = true)
    void revoke(String tokenId, LocalDateTime expiresAt);

    @Modifying
    @Query("delete from RevokedAccessToken token where token.expiresAt < :cutoff")
    int deleteExpired(LocalDateTime cutoff);
}
