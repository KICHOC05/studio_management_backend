package com.codeboost.studio_management_backend;

import org.springframework.boot.SpringApplication;

public class TestStudioManagementBackendApplication {

	public static void main(String[] args) {
		SpringApplication.from(StudioManagementBackendApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
