package org.example.secshare.file;

import jakarta.persistence.*;
import org.hibernate.annotations.ColumnDefault;

import java.time.Instant;
import java.util.UUID;

/**
 * One recipient of an {@link Audience}, identified by (lower-cased) email. A member need not
 * have an account: {@link #token} is a per-recipient secret that unlocks an account-less
 * download link, while a registered member who signs in with the matching address gets access
 * through the audience share directly.
 */
@Entity
@Table(
        name = "audience_members",
        uniqueConstraints = @UniqueConstraint(columnNames = {"audience_id", "email"})
)
public class AudienceMember {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "audience_id", nullable = false)
    private Audience audience;

    @Column(name = "email", nullable = false)
    private String email;

    /** Secret slug for this member's account-less download link; null for legacy members. */
    @Column(name = "token", unique = true, length = 64)
    private String token;

    @Column(name = "opened_at")
    private Instant openedAt;

    @Column(name = "download_count", nullable = false)
    @ColumnDefault("0")
    private int downloadCount = 0;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Audience getAudience() {
        return audience;
    }

    public void setAudience(Audience audience) {
        this.audience = audience;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Instant getOpenedAt() {
        return openedAt;
    }

    public void setOpenedAt(Instant openedAt) {
        this.openedAt = openedAt;
    }

    public int getDownloadCount() {
        return downloadCount;
    }

    public void setDownloadCount(int downloadCount) {
        this.downloadCount = downloadCount;
    }
}
