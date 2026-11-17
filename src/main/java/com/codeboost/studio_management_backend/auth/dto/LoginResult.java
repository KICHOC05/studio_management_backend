package com.codeboost.studio_management_backend.auth.dto;

import com.codeboost.studio_management_backend.auth.services.RefreshTokenService.IssuedRefreshToken;

/** Internal result; controllers must serialize only response(), never this wrapper. */
public record LoginResult(LoginResponse response, IssuedRefreshToken refreshToken) {
    @Override
    public String toString() {
        return "LoginResult[credentials=REDACTED]";
    }
}
