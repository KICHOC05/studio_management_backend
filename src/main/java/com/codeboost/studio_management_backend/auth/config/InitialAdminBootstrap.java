package com.codeboost.studio_management_backend.auth.config;

import com.codeboost.studio_management_backend.auth.services.InitialAdminService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "app.initial-admin.enabled", havingValue = "true")
public class InitialAdminBootstrap implements ApplicationRunner {
    private final InitialAdminService service;
    private final String email;
    private final String password;

    public InitialAdminBootstrap(InitialAdminService service,
                                 @Value("${app.initial-admin.email}") String email,
                                 @Value("${app.initial-admin.password}") String password) {
        this.service = service;
        this.email = email;
        this.password = password;
    }

    @Override
    public void run(ApplicationArguments args) {
        service.createIfMissing(email, password);
    }
}
