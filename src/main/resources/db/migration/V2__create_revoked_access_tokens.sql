CREATE TABLE revoked_access_tokens (
    token_id VARCHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    PRIMARY KEY (token_id),
    INDEX idx_revoked_access_tokens_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Preserve existing role IDs and assignments, including an ADMIN created by bootstrap.
INSERT INTO roles (code)
VALUES ('ADMIN'), ('INSTRUCTOR'), ('CLIENT')
ON DUPLICATE KEY UPDATE code = code;
