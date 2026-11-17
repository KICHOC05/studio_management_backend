package com.codeboost.studio_management_backend.security.ratelimit;

import com.codeboost.studio_management_backend.security.SecurityProblemHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class RateLimitFilter extends OncePerRequestFilter {
    private final RequestRateLimiter limiter;
    private final SecurityProblemHandler problemHandler;

    public RateLimitFilter(RequestRateLimiter limiter, SecurityProblemHandler problemHandler) {
        this.limiter = limiter;
        this.problemHandler = problemHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getServletPath();
        if (path.isEmpty()) {
            path = request.getRequestURI().substring(request.getContextPath().length());
        }
        boolean login = "POST".equals(request.getMethod()) && "/api/auth/login".equals(path);
        // Use the network peer, never an untrusted X-Forwarded-For header.
        boolean refresh = "POST".equals(request.getMethod()) && "/api/auth/refresh".equals(path);
        long retryAfter = limiter.acquire(request.getRemoteAddr(), login, refresh);
        if (retryAfter > 0) {
            problemHandler.tooManyRequests(request, response, retryAfter);
            return;
        }
        filterChain.doFilter(request, response);
    }
}
