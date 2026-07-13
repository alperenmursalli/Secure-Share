package org.example.secshare.file;

import org.example.secshare.auth.security.UserPrincipal;
import org.example.secshare.file.dto.AudienceMemberResponse;
import org.example.secshare.file.dto.CreateShareRequest;
import org.example.secshare.file.dto.PublicShareMetaResponse;
import org.example.secshare.file.dto.ShareResponse;
import org.example.secshare.user.User;
import org.example.secshare.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;

/**
 * Business logic for sharing files, covering both the public token-link model and the
 * per-recipient grant model. Ownership is verified by reusing
 * {@link FileService#getOwnedFileOrThrow}.
 */
@Service
public class FileShareService {

    private static final int TOKEN_BYTES = 24; // ~32 url-safe chars
    private final SecureRandom secureRandom = new SecureRandom();
    private final Base64.Encoder tokenEncoder = Base64.getUrlEncoder().withoutPadding();

    /** Upper bound on recipients per audience — guards against pathological bulk requests. */
    private static final int MAX_AUDIENCE_MEMBERS = 5000;

    private final FileShareRepository fileShareRepository;
    private final AudienceRepository audienceRepository;
    private final AudienceMemberRepository audienceMemberRepository;
    private final FileService fileService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public FileShareService(
            FileShareRepository fileShareRepository,
            AudienceRepository audienceRepository,
            AudienceMemberRepository audienceMemberRepository,
            FileService fileService,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.fileShareRepository = fileShareRepository;
        this.audienceRepository = audienceRepository;
        this.audienceMemberRepository = audienceMemberRepository;
        this.fileService = fileService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ---------------------------------------------------------------------
    // Owner operations
    // ---------------------------------------------------------------------

    @Transactional
    public ShareResponse createShare(UUID fileId, CreateShareRequest req, UserPrincipal principal) {
        SharedFile file = fileService.getOwnedFileOrThrow(fileId, principal);
        User owner = requireUser(principal.userId());

        ShareType type = parseType(req.type());
        FileShare share = new FileShare();
        share.setId(UUID.randomUUID());
        share.setFile(file);
        share.setCreatedBy(owner);
        share.setType(type);
        share.setCreatedAt(Instant.now());

        switch (type) {
            case LINK -> configureLink(share, req);
            case USER -> configureUserGrant(share, file, req);
            case AUDIENCE -> configureAudience(share, owner, req);
        }

        fileShareRepository.save(share);
        return toResponse(share);
    }

    private void configureLink(FileShare share, CreateShareRequest req) {
        share.setToken(generateToken());

        if (req.password() != null && !req.password().isBlank()) {
            share.setPasswordHash(passwordEncoder.encode(req.password()));
        }

        if (req.expiresInMinutes() != null) {
            if (req.expiresInMinutes() <= 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Expiry must be positive");
            }
            share.setExpiresAt(Instant.now().plus(req.expiresInMinutes(), ChronoUnit.MINUTES));
        }

        if (req.maxDownloads() != null) {
            if (req.maxDownloads() <= 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Download limit must be positive");
            }
            share.setMaxDownloads(req.maxDownloads());
        }

        share.setBurnAfterAccess(Boolean.TRUE.equals(req.burnAfterAccess()));
    }

    private void configureUserGrant(FileShare share, SharedFile file, CreateShareRequest req) {
        if (req.recipientEmail() == null || req.recipientEmail().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Recipient email is required");
        }

        User recipient = userRepository.findByEmailIgnoreCase(req.recipientEmail().trim())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No user with that email"));

        if (recipient.getId().equals(file.getOwner().getId())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "You cannot share a file with yourself");
        }

        if (fileShareRepository.existsByFileAndRecipientAndRevokedFalse(file, recipient)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "File is already shared with this user");
        }

        share.setRecipient(recipient);
        share.setBurnMode(parseBurnMode(req.burnMode()));
    }

    /**
     * Configures an AUDIENCE grant: builds (or would reuse) a named email list and attaches it
     * to the share. Emails are normalised (trimmed, lower-cased, de-duplicated) and persisted
     * in one batch so a single share can reach thousands of recipients cheaply.
     */
    private void configureAudience(FileShare share, User owner, CreateShareRequest req) {
        if (req.recipientEmails() == null || req.recipientEmails().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one recipient email is required");
        }

        LinkedHashSet<String> emails = new LinkedHashSet<>();
        for (String raw : req.recipientEmails()) {
            if (raw == null) continue;
            String email = raw.trim().toLowerCase();
            if (email.isEmpty()) continue;
            if (!email.contains("@") || email.length() > 254) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email address: " + raw.trim());
            }
            emails.add(email);
        }
        if (emails.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one valid recipient email is required");
        }
        if (emails.size() > MAX_AUDIENCE_MEMBERS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Too many recipients (max " + MAX_AUDIENCE_MEMBERS + ")");
        }

        Audience audience = new Audience();
        audience.setId(UUID.randomUUID());
        audience.setOwner(owner);
        audience.setName(req.name() != null && !req.name().isBlank()
                ? req.name().trim()
                : emails.size() + " recipients");
        audience.setCreatedAt(Instant.now());
        audienceRepository.save(audience);

        List<AudienceMember> members = emails.stream().map(email -> {
            AudienceMember m = new AudienceMember();
            m.setId(UUID.randomUUID());
            m.setAudience(audience);
            m.setEmail(email);
            m.setToken(generateToken()); // per-recipient account-less download link
            return m;
        }).toList();
        audienceMemberRepository.saveAll(members);

        share.setAudience(audience);
        share.setBurnMode(parseBurnMode(req.burnMode()));

        if (req.expiresInMinutes() != null) {
            if (req.expiresInMinutes() <= 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Expiry must be positive");
            }
            share.setExpiresAt(Instant.now().plus(req.expiresInMinutes(), ChronoUnit.MINUTES));
        }
    }

    @Transactional(readOnly = true)
    public List<ShareResponse> listSharesForFile(UUID fileId, UserPrincipal principal) {
        SharedFile file = fileService.getOwnedFileOrThrow(fileId, principal);
        return fileShareRepository.findByFileAndRevokedFalseOrderByCreatedAtDesc(file)
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public void revokeShare(UUID shareId, UserPrincipal principal) {
        FileShare share = fileShareRepository.findById(shareId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Share not found"));

        if (!share.getCreatedBy().getId().equals(principal.userId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You do not own this share");
        }

        share.setRevoked(true);
        fileShareRepository.save(share);
    }

    /** Recipients (with their account-less links) of an audience share the caller owns. */
    @Transactional(readOnly = true)
    public List<AudienceMemberResponse> listAudienceMembers(UUID shareId, UserPrincipal principal) {
        FileShare share = fileShareRepository.findById(shareId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Share not found"));

        if (!share.getCreatedBy().getId().equals(principal.userId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You do not own this share");
        }
        if (share.getType() != ShareType.AUDIENCE || share.getAudience() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Not an audience share");
        }

        return audienceMemberRepository.findByAudience_IdOrderByEmailAsc(share.getAudience().getId())
                .stream()
                .map(m -> new AudienceMemberResponse(
                        m.getEmail(),
                        m.getToken() != null ? "/share.html?t=" + m.getToken() : null,
                        m.getOpenedAt(),
                        m.getDownloadCount()))
                .toList();
    }

    /** Files granted to the current user via active USER grants or AUDIENCE membership. */
    @Transactional(readOnly = true)
    public List<ShareResponse> listSharedWithMe(UserPrincipal principal) {
        User me = requireUser(principal.userId());

        List<ShareResponse> result = new ArrayList<>();
        fileShareRepository
                .findByRecipientAndTypeAndRevokedFalseOrderByCreatedAtDesc(me, ShareType.USER)
                .stream()
                .filter(s -> !s.getFile().isDeleted())
                .map(this::toResponse)
                .forEach(result::add);

        fileShareRepository
                .findAudienceSharesForEmail(principal.email(), ShareType.AUDIENCE)
                .stream()
                .filter(s -> s.isActive() && !s.getFile().isDeleted())
                .map(this::toResponse)
                .forEach(result::add);

        return result;
    }

    // ---------------------------------------------------------------------
    // Public link operations
    // ---------------------------------------------------------------------

    @Transactional(readOnly = true)
    public PublicShareMetaResponse getPublicMeta(String token) {
        FileShare share = fileShareRepository.findByTokenAndRevokedFalse(token).orElse(null);
        if (share == null) {
            // Fall back to a per-recipient audience token (account-less delivery).
            AudienceMember member = audienceMemberRepository.findByToken(token)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Link not found"));
            share = activeAudienceShare(member.getAudience())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Link not found"));
        }

        SharedFile file = share.getFile();
        boolean available = share.isActive() && !file.isDeleted();
        return new PublicShareMetaResponse(
                file.getOriginalFilename(),
                file.getSizeBytes(),
                file.getContentType(),
                share.hasPassword(),
                available
        );
    }

    /** Resolves either a LINK token or a per-recipient audience token for public download. */
    @Transactional
    public LinkDownload resolvePublicDownload(String token, String password) {
        if (fileShareRepository.findByTokenAndRevokedFalse(token).isPresent()) {
            return resolveLinkForDownload(token, password);
        }
        return resolveAudienceTokenForDownload(token);
    }

    private LinkDownload resolveAudienceTokenForDownload(String token) {
        AudienceMember member = audienceMemberRepository.findByToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Link not found"));
        FileShare share = activeAudienceShare(member.getAudience())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Link not found"));

        if (share.isExpired()) {
            throw new ResponseStatusException(HttpStatus.GONE, "This link has expired");
        }
        if (share.getFile().isDeleted()) {
            throw new ResponseStatusException(HttpStatus.GONE, "This file is no longer available");
        }

        member.setDownloadCount(member.getDownloadCount() + 1);
        if (member.getOpenedAt() == null) {
            member.setOpenedAt(Instant.now());
        }
        audienceMemberRepository.save(member);
        return new LinkDownload(share.getFile(), false);
    }

    private java.util.Optional<FileShare> activeAudienceShare(Audience audience) {
        return fileShareRepository.findFirstByAudienceAndTypeAndRevokedFalse(audience, ShareType.AUDIENCE);
    }

    /**
     * Validates a share link (revocation, expiry, download limit, password) and, on
     * success, increments the download counter and returns the file to serve.
     *
     * <p>For a burn link, the file's bytes are destroyed once every allowed download has
     * been spent (or after the first download when no limit is set). On that final download
     * the share is revoked in the same transaction so the token can never resolve again; the
     * caller is then responsible for destroying the file's bytes (see
     * {@link LinkDownload#burn()}). Note: revocation here is best-effort
     * against races — two simultaneous requests could both pass the {@code revokedFalse}
     * lookup before either commits. A pessimistic lock would close that window entirely.</p>
     */
    @Transactional
    public LinkDownload resolveLinkForDownload(String token, String password) {
        FileShare share = fileShareRepository.findByTokenAndRevokedFalse(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Link not found"));

        if (share.isExpired()) {
            throw new ResponseStatusException(HttpStatus.GONE, "This link has expired");
        }
        if (share.isDownloadLimitReached()) {
            throw new ResponseStatusException(HttpStatus.GONE, "This link's download limit has been reached");
        }
        if (share.getFile().isDeleted()) {
            throw new ResponseStatusException(HttpStatus.GONE, "This file is no longer available");
        }

        if (share.hasPassword()) {
            if (password == null || !passwordEncoder.matches(password, share.getPasswordHash())) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Incorrect password");
            }
        }

        share.setDownloadCount(share.getDownloadCount() + 1);

        // Burn is coupled to the download limit: the file is destroyed only once every
        // allowed download has been spent. With no limit set, a single download exhausts it.
        boolean burnNow = share.isBurnAfterAccess()
                && (share.getMaxDownloads() == null || share.isDownloadLimitReached());
        if (burnNow) {
            share.setRevoked(true); // spent: the link can never resolve again
        }
        fileShareRepository.save(share);
        return new LinkDownload(share.getFile(), burnNow);
    }

    // ---------------------------------------------------------------------
    // Authenticated (USER grant) download
    // ---------------------------------------------------------------------

    /**
     * Records that the current principal opened a file granted to them and decides whether
     * that open triggers the grant's {@link BurnMode self-destruct policy}. Returns
     * {@code true} when the caller must destroy the file's bytes after serving them.
     *
     * <p>Only recipient opens count: the owner downloading their own file never burns it,
     * and grants with {@link BurnMode#NONE} never burn. {@link BurnMode#FIRST} burns on the
     * first recipient open; {@link BurnMode#ALL} burns only once every active recipient of
     * the file has opened it at least once.</p>
     */
    @Transactional
    public boolean recordUserAccessAndMaybeBurn(UUID fileId, UserPrincipal principal) {
        FileShare share = fileShareRepository
                .findByFile_IdAndRecipient_IdAndRevokedFalse(fileId, principal.userId())
                .orElse(null);
        if (share == null || share.getType() != ShareType.USER) {
            return false; // owner (or no active grant): nothing to record, never burns
        }

        share.setDownloadCount(share.getDownloadCount() + 1);
        fileShareRepository.save(share);

        return switch (share.getBurnMode()) {
            case FIRST -> true;
            case ALL -> fileShareRepository
                    .findByFile_IdAndTypeAndRevokedFalse(fileId, ShareType.USER)
                    .stream()
                    .allMatch(g -> g.getDownloadCount() > 0);
            case NONE -> false;
        };
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private ShareType parseType(String raw) {
        if (raw == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Share type is required");
        }
        try {
            return ShareType.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid share type");
        }
    }

    private BurnMode parseBurnMode(String raw) {
        if (raw == null || raw.isBlank()) {
            return BurnMode.NONE;
        }
        try {
            return BurnMode.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid burn mode");
        }
    }

    private String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return tokenEncoder.encodeToString(bytes);
    }

    private User requireUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    private ShareResponse toResponse(FileShare share) {
        String url = share.getType() == ShareType.LINK ? "/share.html?t=" + share.getToken() : null;

        String audienceName = null;
        Integer recipientCount = null;
        if (share.getAudience() != null) {
            audienceName = share.getAudience().getName();
            recipientCount = (int) audienceMemberRepository.countByAudience_Id(share.getAudience().getId());
        }

        return new ShareResponse(
                share.getId(),
                share.getType().name(),
                share.getFile().getId(),
                share.getFile().getOriginalFilename(),
                url,
                share.getRecipient() != null ? share.getRecipient().getEmail() : null,
                audienceName,
                recipientCount,
                share.hasPassword(),
                share.getExpiresAt(),
                share.getMaxDownloads(),
                share.getDownloadCount(),
                share.isBurnAfterAccess(),
                share.getBurnMode().name(),
                share.isRevoked(),
                share.isActive(),
                share.getCreatedAt()
        );
    }
}
