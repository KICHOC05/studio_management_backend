package com.codeboost.studio_management_backend.auth.dto;

import java.util.List;

public record AuthenticatedUser(String publicId, String email, List<String> roles) {
}
