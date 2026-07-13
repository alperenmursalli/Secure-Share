package org.example.secshare.file;

import org.example.secshare.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface FileShareRepository extends JpaRepository<FileShare, UUID> {

    Optional<FileShare> findByTokenAndRevokedFalse(String token);

    List<FileShare> findByFileAndRevokedFalseOrderByCreatedAtDesc(SharedFile file);

    List<FileShare> findByRecipientAndTypeAndRevokedFalseOrderByCreatedAtDesc(User recipient, ShareType type);

    boolean existsByFileAndRecipientAndRevokedFalse(SharedFile file, User recipient);

    boolean existsByFile_IdAndRecipient_IdAndRevokedFalse(UUID fileId, UUID recipientId);

    Optional<FileShare> findByFile_IdAndRecipient_IdAndRevokedFalse(UUID fileId, UUID recipientId);

    List<FileShare> findByFile_IdAndTypeAndRevokedFalse(UUID fileId, ShareType type);

    /** Live burn-after-reading links — candidates the reaper inspects for expiry. */
    List<FileShare> findByBurnAfterAccessTrueAndRevokedFalse();

    /** Ids of the audiences a file is actively shared to (used for the access check). */
    @Query("select fs.audience.id from FileShare fs " +
            "where fs.file.id = :fileId and fs.type = :type and fs.revoked = false")
    List<UUID> findActiveAudienceIds(@Param("fileId") UUID fileId, @Param("type") ShareType type);

    /** The active share that exposes a given audience (audiences map 1:1 to a share). */
    Optional<FileShare> findFirstByAudienceAndTypeAndRevokedFalse(Audience audience, ShareType type);

    /** Active audience shares whose audience includes the given recipient email. */
    @Query("select distinct fs from FileShare fs join fs.audience a " +
            "where fs.type = :type and fs.revoked = false and exists " +
            "(select 1 from AudienceMember m where m.audience = a and lower(m.email) = lower(:email))")
    List<FileShare> findAudienceSharesForEmail(@Param("email") String email, @Param("type") ShareType type);
}
