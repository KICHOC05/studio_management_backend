package com.codeboost.studio_management_backend.security.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

/** Thread-safe fixed windows, bounded in memory. Limits apply per application instance. */
@Component
public class RequestRateLimiter {
    private final RateLimitProperties properties;
    private final Clock clock;
    private final Map<String, Window> clients = new HashMap<>();

    public RequestRateLimiter(RateLimitProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /** Returns zero when allowed, otherwise the number of seconds before retrying. */
    public synchronized long acquire(String client, boolean login) {
        return acquire(client, login, false);
    }

    public synchronized long acquire(String client, boolean login, boolean refresh) {
        long now = clock.millis();
        long duration = properties.getWindowSeconds() * 1000L;
        Window window = clients.get(client);
        if (window == null) {
            // Purge expired entries before admitting a new client at capacity.
            if (clients.size() >= properties.getMaxClients()) {
                clients.values().removeIf(value -> now >= Math.max(value.expiresAt,
                        Math.max(value.loginExpiresAt, value.refreshExpiresAt)));
                if (clients.size() >= properties.getMaxClients()) {
                    // Fail closed rather than evicting active counters and allowing limit bypass.
                    return properties.getWindowSeconds();
                }
            }
            window = new Window(now + duration);
            clients.put(client, window);
        }
        if (now >= window.expiresAt) {
            window.expiresAt = now + duration;
            window.requests = 0;
        }
        if (window.requests >= properties.getRequests()) {
            return retryAfter(window.expiresAt - now);
        }
        window.requests++;
        if (login) {
            if (window.loginExpiresAt == 0 || now >= window.loginExpiresAt) {
                window.loginExpiresAt = now + duration;
                window.loginRequests = 0;
            }
            if (window.loginRequests >= properties.getLoginRequests()) {
                return retryAfter(window.loginExpiresAt - now);
            }
            window.loginRequests++;
        }
        if (refresh) {
            if (window.refreshExpiresAt == 0 || now >= window.refreshExpiresAt) {
                window.refreshExpiresAt = now + duration;
                window.refreshRequests = 0;
            }
            if (window.refreshRequests >= properties.getRefreshRequests()) {
                return retryAfter(window.refreshExpiresAt - now);
            }
            window.refreshRequests++;
        }
        return 0;
    }

    private long retryAfter(long millis) {
        return Math.max(1, (millis + 999) / 1000);
    }

    private static class Window {
        private long expiresAt;
        private long loginExpiresAt;
        private int requests;
        private int loginRequests;
        private int refreshRequests;
        private long refreshExpiresAt;

        private Window(long expiresAt) {
            this.expiresAt = expiresAt;
        }
    }
}
