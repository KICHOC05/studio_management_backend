package com.codeboost.studio_management_backend.auth.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app.refresh-token")
@Validated
@Getter
@Setter
public class RefreshTokenProperties {
    @Min(1)
    @Max(90)
    private int lifetimeDays = 7;
    private boolean cookieSecure = true;
}
