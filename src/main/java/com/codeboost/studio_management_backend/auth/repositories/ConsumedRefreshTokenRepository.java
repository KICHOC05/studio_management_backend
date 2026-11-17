package com.codeboost.studio_management_backend.auth.repositories;

import com.codeboost.studio_management_backend.auth.models.ConsumedRefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ConsumedRefreshTokenRepository extends JpaRepository<ConsumedRefreshToken, String> {
    @Query("select t.session.id from ConsumedRefreshToken t where t.tokenHash = :hash")
    Optional<Long> findSessionIdByHash(String hash);
}
