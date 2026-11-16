package com.codeboost.studio_management_backend.auth.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "revoked_access_tokens", indexes =
        @Index(name = "idx_revoked_access_tokens_expires_at", columnList = "expires_at"))
@Getter
@NoArgsConstructor
public class RevokedAccessToken {
    @Id
    @Column(name = "token_id", nullable = false, length = 36,
            columnDefinition = "VARCHAR(36) CHARACTER SET ascii COLLATE ascii_bin")
    private String tokenId;

    @Column(name = "expires_at", nullable = false, columnDefinition = "DATETIME(6)")
    private LocalDateTime expiresAt;
}
