package com.codeboost.studio_management_backend.security.ratelimit;

import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app.rate-limit")
@Validated
@Getter
@Setter
public class RateLimitProperties {
    @Min(1)
    private int requests = 120;
    @Min(1)
    private int loginRequests = 5;
    @Min(1)
    private int refreshRequests = 10;
    @Min(1)
    private int windowSeconds = 60;
    @Min(1)
    private int maxClients = 10000;
}
