package com.codeboost.studio_management_backend.auth.dto;

public record LoginResponse(String accessToken, String tokenType, long expiresIn, AuthenticatedUser user) {
    @Override
    public String toString() {
        return "LoginResponse[token=REDACTED]";
    }
}
