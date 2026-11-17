-- auth_sessions keeps the current refresh hash and the absolute session expiry.
-- This table retains previous hashes to detect reuse after rotation.
-- Only SHA-256 hexadecimal hashes are stored, never the original tokens.
CREATE TABLE consumed_refresh_tokens (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    session_id BIGINT NOT NULL,
    consumed_at DATETIME(6) NOT NULL,
    PRIMARY KEY (token_hash),
    INDEX idx_consumed_refresh_tokens_session_id (session_id),
    CONSTRAINT fk_consumed_refresh_tokens_session
        FOREIGN KEY (session_id) REFERENCES auth_sessions (id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Future rotation must insert the old hash and update the current hash atomically.
-- consumed_at must be supplied in UTC by the application.
-- Retain history until the session's absolute expiry plus clock-skew tolerance.
-- Delete a session's history before deleting the session itself.
