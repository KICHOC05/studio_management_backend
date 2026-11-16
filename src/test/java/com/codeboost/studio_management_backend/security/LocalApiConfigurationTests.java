package com.codeboost.studio_management_backend.security;

import com.codeboost.studio_management_backend.common.exceptions.GlobalExceptionHandler;
import com.codeboost.studio_management_backend.auth.controllers.AuthController;
import com.codeboost.studio_management_backend.auth.dto.AuthenticatedUser;
import com.codeboost.studio_management_backend.auth.dto.LoginResponse;
import com.codeboost.studio_management_backend.auth.services.AuthService;
import com.codeboost.studio_management_backend.auth.services.JwtService;
import com.codeboost.studio_management_backend.auth.services.LogoutService;
import com.codeboost.studio_management_backend.auth.repositories.RevokedAccessTokenRepository;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.authentication.BadCredentialsException;
import java.time.Clock;
import java.util.List;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithAnonymousUser;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.mockito.Mockito.*;

@SpringJUnitConfig(LocalApiConfigurationTests.TestConfig.class)
@WebAppConfiguration
@ActiveProfiles("local")
@WithMockUser
@TestPropertySource(properties = {
        "app.jwt.secret=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        "app.jwt.issuer=studio-management-backend"
})
class LocalApiConfigurationTests {

    private MockMvc mvc;
    private AuthService authService;
    private JwtService jwtService;
    private RevokedAccessTokenRepository revokedTokens;

    @BeforeEach
    void setUp(WebApplicationContext context) {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        authService = org.springframework.test.util.AopTestUtils.getUltimateTargetObject(context.getBean(AuthService.class));
        reset(authService);
        revokedTokens = context.getBean(RevokedAccessTokenRepository.class);
        reset(revokedTokens);
        jwtService = new JwtService(context.getBean(JwtEncoder.class), Clock.systemUTC(), "studio-management-backend", 15);
    }

    @Test
    void permitsAuthenticatedPostWithoutCsrfToken() throws Exception {
        mvc.perform(post("/test/input").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Ana\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @WithAnonymousUser
    void rejectsAnonymousPrivateRequestsEvenWithLocalProfile() throws Exception {
        mvc.perform(get("/test/not-found"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @WithAnonymousUser
    void permitsAnonymousLogin() throws Exception {
        AuthenticatedUser user = new AuthenticatedUser("public-id", "admin@example.com", List.of("ADMIN"));
        when(authService.login(any())).thenReturn(new LoginResponse("signed-token", "Bearer", 900, user));
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"admin@example.com\",\"password\":\"initial-password\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.accessToken").value("signed-token"))
                .andExpect(jsonPath("$.user.publicId").value("public-id"))
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist());
    }

    @Test
    @WithAnonymousUser
    void invalidLoginIsUnauthorizedAndInvalidInputIsBadRequest() throws Exception {
        when(authService.login(any())).thenThrow(new BadCredentialsException("private details"));
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"admin@example.com\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Se requiere autenticacion valida."));
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"invalid\",\"password\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithAnonymousUser
    void acceptsSignedTokenAndMapsAdminRole() throws Exception {
        AuthenticatedUser user = new AuthenticatedUser("public-id", "admin@example.com", List.of("ADMIN"));
        String token = jwtService.issueToken(user).accessToken();
        when(authService.currentUser("public-id")).thenReturn(user);
        mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicId").value("public-id"));
        mvc.perform(get("/test/admin").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        String userToken = jwtService.issueToken(new AuthenticatedUser("other-id", "user@example.com", List.of("USER"))).accessToken();
        mvc.perform(get("/test/admin").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithAnonymousUser
    void rejectsInvalidBearerTokens() throws Exception {
        mvc.perform(get("/test/not-found").header("Authorization", "Bearer invalid.jwt.token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @WithAnonymousUser
    void logoutRevokesOnlyPresentedTokenAndRejectsReuse() throws Exception {
        var user = new AuthenticatedUser("public-id", "admin@example.com", List.of("ADMIN"));
        String token = jwtService.issueToken(user).accessToken();
        String otherToken = jwtService.issueToken(user).accessToken();
        java.util.Set<String> revoked = new java.util.HashSet<>();
        when(revokedTokens.existsById(anyString())).thenAnswer(invocation -> revoked.contains(invocation.getArgument(0)));
        doAnswer(invocation -> { revoked.add(invocation.getArgument(0)); return null; })
                .when(revokedTokens).revoke(anyString(), any());
        when(authService.currentUser("public-id")).thenReturn(user);

        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(content().string(""));
        mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + otherToken))
                .andExpect(status().isOk());
        verify(revokedTokens, times(1)).revoke(anyString(), any());
    }

    @Test
    @WithAnonymousUser
    void logoutRequiresValidBearerToken() throws Exception {
        mvc.perform(post("/api/auth/logout")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer invalid.jwt.token"))
                .andExpect(status().isUnauthorized());
        verify(revokedTokens, never()).revoke(anyString(), any());
    }

    @Test
    void returnsForbiddenForInsufficientRole() throws Exception {
        mvc.perform(get("/test/admin"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    @WithAnonymousUser
    void loginRateLimitReturnsRetryAfterAndCannotBeBypassedWithForwardedHeader() throws Exception {
        when(authService.login(any())).thenThrow(new BadCredentialsException("Invalid credentials"));
        for (int i = 0; i < 6; i++) {
            var result = mvc.perform(post("/api/auth/login")
                    .with(request -> { request.setRemoteAddr("192.0.2.20"); return request; })
                    .header("X-Forwarded-For", "203.0.113." + i)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"email\":\"admin@example.com\",\"password\":\"wrong\"}"));
            if (i < 5) {
                result.andExpect(status().isUnauthorized());
            } else {
                result.andExpect(status().isTooManyRequests())
                        .andExpect(header().exists("Retry-After"))
                        .andExpect(header().string("Cache-Control", "no-store"))
                        .andExpect(jsonPath("$.status").value(429));
            }
        }
        verify(authService, times(5)).login(any());
    }

    @Test
    @WithAnonymousUser
    void limitsAllRequestsBeforeJwtValidation() throws Exception {
        for (int i = 0; i < 121; i++) {
            mvc.perform(get("/api/auth/me")
                            .with(request -> { request.setRemoteAddr("192.0.2.21"); return request; }))
                    .andExpect(i < 120 ? status().isUnauthorized() : status().isTooManyRequests());
        }
    }

    @Test
    void returnsFieldErrorsWithoutRejectedValues() throws Exception {
        mvc.perform(post("/test/input").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errors[0].field").value("name"))
                .andExpect(jsonPath("$.errors[0].rejectedValue").doesNotExist());
    }

    @Test
    void malformedJsonIsBadRequest() throws Exception {
        mvc.perform(post("/test/input").contentType(MediaType.APPLICATION_JSON).content("{"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void integrityConflictDoesNotExposeDatabaseDetails() throws Exception {
        mvc.perform(get("/test/conflict"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail").value(
                        "La operacion entra en conflicto con los datos existentes o sus relaciones."));
    }

    @Test
    void unexpectedErrorDoesNotExposeInternalMessage() throws Exception {
        mvc.perform(get("/test/unexpected"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.detail").value(
                        "Ocurrio un error interno. Intentalo de nuevo mas tarde."));
    }

    @Test
    void preservesNotFoundAndMethodNotAllowedStatuses() throws Exception {
        mvc.perform(get("/test/not-found"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.detail").value("Usuario no encontrado"));
        mvc.perform(get("/test/input"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Configuration
    @EnableWebMvc
    @EnableWebSecurity
    @Import({SecurityConfig.class, JwtConfig.class, SecurityProblemHandler.class,
            GlobalExceptionHandler.class, AuthController.class, TestController.class,
            com.codeboost.studio_management_backend.security.ratelimit.RequestRateLimiter.class})
    static class TestConfig {
        @Bean
        RevokedAccessTokenRepository revokedTokens() {
            return mock(RevokedAccessTokenRepository.class);
        }

        @Bean
        LogoutService logoutService(RevokedAccessTokenRepository tokens) {
            return new LogoutService(tokens);
        }
        @Bean
        JsonMapper jsonMapper() {
            return JsonMapper.builder().build();
        }

        @Bean
        AuthService authService() {
            return mock(AuthService.class);
        }
    }

    @RestController
    static class TestController {

        @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
        @GetMapping("/test/admin")
        public void admin() {
        }

        @PostMapping("/test/input")
        public void input(@Valid @RequestBody TestInput input) {
        }

        @GetMapping("/test/conflict")
        public void conflict() {
            throw new DataIntegrityViolationException("SQL private database details");
        }

        @GetMapping("/test/unexpected")
        public void unexpected() {
            throw new IllegalStateException("private internal details");
        }

        @GetMapping("/test/not-found")
        public void notFound() {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no encontrado");
        }
    }

    record TestInput(@NotBlank String name) {
    }
}
