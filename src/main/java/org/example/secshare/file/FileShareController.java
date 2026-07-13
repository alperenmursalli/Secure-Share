package org.example.secshare.file;

import org.example.secshare.auth.security.UserPrincipal;
import org.example.secshare.file.dto.AudienceMemberResponse;
import org.example.secshare.file.dto.CreateShareRequest;
import org.example.secshare.file.dto.ShareResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Authenticated share management: owners create/list/revoke shares on their files, and
 * recipients list files shared with them.
 */
@RestController
@RequestMapping("/api/files")
public class FileShareController {

    private final FileShareService fileShareService;

    public FileShareController(FileShareService fileShareService) {
        this.fileShareService = fileShareService;
    }

    @PostMapping("/{id}/shares")
    public ShareResponse createShare(
            @PathVariable("id") UUID fileId,
            @RequestBody CreateShareRequest request,
            @AuthenticationPrincipal UserPrincipal user
    ) {
        return fileShareService.createShare(fileId, request, user);
    }

    @GetMapping("/{id}/shares")
    public List<ShareResponse> listShares(
            @PathVariable("id") UUID fileId,
            @AuthenticationPrincipal UserPrincipal user
    ) {
        return fileShareService.listSharesForFile(fileId, user);
    }

    @DeleteMapping("/shares/{shareId}")
    public ResponseEntity<Void> revokeShare(
            @PathVariable("shareId") UUID shareId,
            @AuthenticationPrincipal UserPrincipal user
    ) {
        fileShareService.revokeShare(shareId, user);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/shares/{shareId}/members")
    public List<AudienceMemberResponse> audienceMembers(
            @PathVariable("shareId") UUID shareId,
            @AuthenticationPrincipal UserPrincipal user
    ) {
        return fileShareService.listAudienceMembers(shareId, user);
    }

    @GetMapping("/shared-with-me")
    public List<ShareResponse> sharedWithMe(@AuthenticationPrincipal UserPrincipal user) {
        return fileShareService.listSharedWithMe(user);
    }
}
