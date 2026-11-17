package com.codeboost.studio_management_backend.auth.services;

import org.springframework.security.authentication.BadCredentialsException;

/** Does not roll back a session revocation caused by refresh-token reuse. */
public class RefreshTokenRejectedException extends BadCredentialsException {
    public RefreshTokenRejectedException() {
        super("Refresh token no valido");
    }
}
