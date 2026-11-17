package com.codeboost.studio_management_backend.security;

import jakarta.validation.constraints.AssertTrue;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("app.cors")
@Validated
@Getter
@Setter
public class CorsProperties {
    private List<String> allowedOrigins = new ArrayList<>();

    @AssertTrue(message = "CORS requiere origenes http/https explicitos, sin comodines, rutas ni credenciales")
    public boolean isOriginsValid() {
        if (allowedOrigins == null) return false;
        return allowedOrigins.stream().allMatch(origin -> {
            try {
                URI uri = URI.create(origin);
                return ("https".equals(uri.getScheme()) || "http".equals(uri.getScheme()))
                        && uri.getHost() != null && !origin.contains("*")
                        && uri.getUserInfo() == null && uri.getRawQuery() == null && uri.getRawFragment() == null
                        && (uri.getRawPath() == null || uri.getRawPath().isEmpty())
                        && (uri.getPort() == -1 || uri.getPort() > 0 && uri.getPort() <= 65535);
            } catch (IllegalArgumentException | NullPointerException ex) {
                return false;
            }
        });
    }
}
