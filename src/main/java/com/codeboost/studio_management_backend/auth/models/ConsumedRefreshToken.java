package com.codeboost.studio_management_backend.auth.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "consumed_refresh_tokens", indexes =
        @Index(name = "idx_consumed_refresh_tokens_session_id", columnList = "session_id"))
@Getter
@NoArgsConstructor
public class ConsumedRefreshToken {
    @Id
    @Column(name = "token_hash", nullable = false, length = 64,
            columnDefinition = "CHAR(64) CHARACTER SET ascii COLLATE ascii_bin")
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_consumed_refresh_tokens_session"))
    private AuthSession session;

    @Column(name = "consumed_at", nullable = false, columnDefinition = "DATETIME(6)")
    private LocalDateTime consumedAt;

    public ConsumedRefreshToken(String tokenHash, AuthSession session, LocalDateTime consumedAt) {
        this.tokenHash = tokenHash;
        this.session = session;
        this.consumedAt = consumedAt;
    }
}
