package org.example.secshare.file.dto;

import java.time.Instant;
import java.util.UUID;

public record FileInfoResponse(
        UUID id,
        String name,
        long sizeBytes,
        String contentType,
        Instant createdAt
) {
}

