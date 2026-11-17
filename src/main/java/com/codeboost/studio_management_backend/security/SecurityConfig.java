package com.codeboost.studio_management_backend.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.codeboost.studio_management_backend.security.ratelimit.RateLimitProperties;
import com.codeboost.studio_management_backend.security.ratelimit.RequestRateLimiter;
import com.codeboost.studio_management_backend.security.ratelimit.RateLimitFilter;
import jakarta.servlet.DispatcherType;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import com.codeboost.studio_management_backend.auth.config.RefreshTokenProperties;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(RateLimitProperties.class)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SecurityProblemHandler problemHandler,
                                                   RequestRateLimiter rateLimiter, RefreshTokenProperties refreshProperties,
                                                   UrlBasedCorsConfigurationSource corsConfigurationSource) throws Exception {
        var refreshEndpoint = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/api/auth/refresh");
        var logoutEndpoint = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/api/auth/logout");
        var cookieEndpoints = new OrRequestMatcher(refreshEndpoint, logoutEndpoint);
        var csrfRepository = new CookieCsrfTokenRepository();
        csrfRepository.setCookiePath("/api/auth");
        csrfRepository.setCookieCustomizer(cookie -> cookie.httpOnly(true)
                .secure(refreshProperties.isCookieSecure()).sameSite("Strict"));
        var bearerResolver = new DefaultBearerTokenResolver();
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("roles");
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .addFilterBefore(new RateLimitFilter(rateLimiter, problemHandler), CsrfFilter.class)
                .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository).requireCsrfProtectionMatcher(cookieEndpoints))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/refresh", "/api/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/csrf").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(errors -> errors.authenticationEntryPoint(problemHandler).accessDeniedHandler(problemHandler))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .bearerTokenResolver(request -> {
                            boolean refreshCookie = request.getCookies() != null && Arrays.stream(request.getCookies())
                                    .anyMatch(cookie -> "refresh_token".equals(cookie.getName()));
                            if (refreshEndpoint.matches(request) || logoutEndpoint.matches(request) && refreshCookie) return null;
                            return bearerResolver.resolve(request);
                        })
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(converter))
                        .authenticationEntryPoint(problemHandler)
                        .accessDeniedHandler(problemHandler))
                .build();
    }
}
