package com.codeboost.studio_management_backend.auth.controllers;

import com.codeboost.studio_management_backend.auth.dto.AuthenticatedUser;
import com.codeboost.studio_management_backend.auth.dto.LoginRequest;
import com.codeboost.studio_management_backend.auth.dto.LoginResponse;
import com.codeboost.studio_management_backend.auth.services.AuthService;
import com.codeboost.studio_management_backend.auth.services.LogoutService;
import com.codeboost.studio_management_backend.auth.services.RefreshTokenCookieService;
import com.codeboost.studio_management_backend.auth.services.RefreshRotationService;
import com.codeboost.studio_management_backend.auth.services.RefreshTokenRejectedException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.http.ProblemDetail;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;
    private final LogoutService logoutService;
    private final RefreshTokenCookieService cookies;
    private final RefreshRotationService refreshRotation;

    public AuthController(AuthService authService, LogoutService logoutService, RefreshTokenCookieService cookies,
                          RefreshRotationService refreshRotation) {
        this.authService = authService;
        this.logoutService = logoutService;
        this.cookies = cookies;
        this.refreshRotation = refreshRotation;
    }

    @PostMapping("/login")
    @PreAuthorize("permitAll()")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        var result = authService.login(request);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .header(HttpHeaders.SET_COOKIE, cookies.issue(result.refreshToken()).toString())
                .body(result.response());
    }

    @GetMapping("/csrf")
    @PreAuthorize("permitAll()")
    public ResponseEntity<CsrfResponse> csrf(CsrfToken csrf) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(new CsrfResponse(csrf.getHeaderName(), csrf.getToken()));
    }

    @PostMapping("/refresh")
    @PreAuthorize("permitAll()")
    public ResponseEntity<LoginResponse> refresh(@CookieValue(name = "refresh_token", required = false) String token) {
        var result = refreshRotation.refresh(token);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .header(HttpHeaders.SET_COOKIE, cookies.issue(result.refreshToken()).toString())
                .body(result.response());
    }

    @ExceptionHandler(RefreshTokenRejectedException.class)
    public ResponseEntity<ProblemDetail> rejectedRefresh() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, cookies.clear().toString())
                .body(ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Refresh token no valido."));
    }

    public record CsrfResponse(String headerName, String token) {
    }

    @PostMapping("/logout")
    @PreAuthorize("permitAll()")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal Jwt jwt,
                                       @CookieValue(name = "refresh_token", required = false) String refresh) {
        if (refresh != null) {
            logoutService.logoutByRefresh(refresh);
        } else if (jwt != null) {
            logoutService.logout(jwt);
        } else {
            throw new RefreshTokenRejectedException();
        }
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, cookies.clear().toString()).build();
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<AuthenticatedUser> me(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(authService.currentUser(jwt.getSubject()));
    }
}
