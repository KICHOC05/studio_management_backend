package com.codeboost.studio_management_backend.auth.models;

import com.codeboost.studio_management_backend.user.models.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "auth_sessions",
        uniqueConstraints = @UniqueConstraint(name = "uk_auth_sessions_refresh_token_hash",
                columnNames = "refresh_token_hash"),
        indexes = @Index(name = "idx_auth_sessions_user_id", columnList = "user_id"))
@Getter
@Setter
@NoArgsConstructor
public class AuthSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_auth_sessions_user"))
    private User user;

    @Column(name = "refresh_token_hash", nullable = false, length = 255,
            columnDefinition = "VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin")
    private String refreshTokenHash;

    @Column(name = "expires_at", nullable = false, columnDefinition = "DATETIME(6)")
    private LocalDateTime expiresAt;

    @Column(name = "revoked_at", columnDefinition = "DATETIME(6)")
    private LocalDateTime revokedAt;
}
