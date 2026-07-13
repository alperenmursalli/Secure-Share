package org.example.secshare.file.dto;

import java.time.Instant;

/**
 * One recipient of an audience share, as shown to the owner (e.g. for exporting the
 * per-recipient links). {@code url} is the account-less download link, or null for legacy
 * members created before tokenised delivery.
 */
public record AudienceMemberResponse(
        String email,
        String url,
        Instant openedAt,
        int downloadCount
) {
}
