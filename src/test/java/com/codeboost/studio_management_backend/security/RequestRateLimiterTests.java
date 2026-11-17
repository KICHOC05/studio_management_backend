package com.codeboost.studio_management_backend.security;

import com.codeboost.studio_management_backend.security.ratelimit.RateLimitProperties;
import com.codeboost.studio_management_backend.security.ratelimit.RequestRateLimiter;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RequestRateLimiterTests {
    private final AtomicLong now = new AtomicLong(1000);
    private final RateLimitProperties properties = new RateLimitProperties();

    private RequestRateLimiter limiter() {
        Clock clock = mock(Clock.class);
        when(clock.millis()).thenAnswer(invocation -> now.get());
        return new RequestRateLimiter(properties, clock);
    }

    @Test
    void separatesClientsAndResetsAfterWindow() {
        properties.setRequests(2);
        var limiter = limiter();
        assertEquals(0, limiter.acquire("first", false));
        assertEquals(0, limiter.acquire("first", false));
        assertEquals(60, limiter.acquire("first", false));
        assertEquals(0, limiter.acquire("second", false));
        now.addAndGet(60000);
        assertEquals(0, limiter.acquire("first", false));
    }

    @Test
    void loginLimitSurvivesGeneralWindowReset() {
        properties.setLoginRequests(1);
        var limiter = limiter();
        limiter.acquire("ip", false);
        now.addAndGet(30000);
        assertEquals(0, limiter.acquire("ip", true));
        assertEquals(60, limiter.acquire("ip", true));
        assertEquals(0, limiter.acquire("ip", false));
        now.addAndGet(30000);
        assertEquals(30, limiter.acquire("ip", true));
        now.addAndGet(30000);
        assertEquals(0, limiter.acquire("ip", true));
    }

    @Test
    void boundsMemoryWithoutEvictingActiveLimits() {
        properties.setMaxClients(1);
        var limiter = limiter();
        assertEquals(0, limiter.acquire("first", false));
        assertEquals(60, limiter.acquire("second", false));
        now.addAndGet(60000);
        assertEquals(0, limiter.acquire("second", false));
    }

    @Test
    void refreshQuotaIsIndependentFromLoginAndRecoversAfterWindow() {
        properties.setRefreshRequests(2);
        var limiter = limiter();
        assertEquals(0, limiter.acquire("ip", false, true));
        assertEquals(0, limiter.acquire("ip", false, true));
        assertEquals(60, limiter.acquire("ip", false, true));
        assertEquals(0, limiter.acquire("ip", true, false));
        now.addAndGet(60000);
        assertEquals(0, limiter.acquire("ip", false, true));
    }

    @Test
    void concurrentRequestsCannotExceedQuota() throws Exception {
        properties.setRequests(5);
        var limiter = limiter();
        try (var executor = Executors.newFixedThreadPool(8)) {
            var tasks = new ArrayList<Callable<Long>>();
            for (int i = 0; i < 40; i++) {
                tasks.add(() -> limiter.acquire("ip", false));
            }
            long allowed = 0;
            for (var result : executor.invokeAll(tasks)) {
                if (result.get() == 0) allowed++;
            }
            assertEquals(5, allowed);
        }
    }
}
