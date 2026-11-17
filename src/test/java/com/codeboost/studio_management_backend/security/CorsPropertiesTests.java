package com.codeboost.studio_management_backend.security;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class CorsPropertiesTests {
    @Test
    void allowsOnlyExplicitHttpOrigins() {
        var properties = new CorsProperties();
        properties.setAllowedOrigins(List.of("http://localhost:5173", "https://studio.example.com"));
        assertTrue(properties.isOriginsValid());
        for (String invalid : List.of("*", "https://*.example.com", "null", "https://example.com/path",
                "https://user:password@example.com", "https://example.com/", "ftp://example.com", "http://localhost:99999")) {
            properties.setAllowedOrigins(List.of(invalid));
            assertFalse(properties.isOriginsValid(), invalid);
        }
    }
}
