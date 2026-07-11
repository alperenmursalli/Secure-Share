package org.example.secshare.auth.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record MeResponse(
        UUID id,
        String email,
        List<String> roles,
        Instant createdAt
) {}
