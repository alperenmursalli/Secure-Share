package org.example.secshare.file;

import org.example.secshare.file.dto.DownloadShareRequest;
import org.example.secshare.file.dto.PublicShareMetaResponse;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Public, unauthenticated endpoints backing the share-link download page. Access is
 * gated entirely by the secret token plus the link's own protections (password, expiry,
 * download limit, revocation).
 */
@RestController
@RequestMapping("/api/public/shares")
public class PublicShareController {

    private final FileShareService fileShareService;
    private final FileService fileService;

    public PublicShareController(FileShareService fileShareService, FileService fileService) {
        this.fileShareService = fileShareService;
        this.fileService = fileService;
    }

    @GetMapping("/{token}")
    public PublicShareMetaResponse meta(@PathVariable("token") String token) {
        return fileShareService.getPublicMeta(token);
    }

    @PostMapping("/{token}/download")
    public ResponseEntity<Resource> download(
            @PathVariable("token") String token,
            @RequestBody(required = false) DownloadShareRequest request
    ) {
        String password = request != null ? request.password() : null;
        LinkDownload dl = fileShareService.resolvePublicDownload(token, password);
        SharedFile file = dl.file();

        final Resource resource;
        if (dl.burn()) {
            // Capture the bytes, then irreversibly destroy the file before responding.
            byte[] content = fileService.readAllBytes(file);
            fileService.purge(file);
            resource = fileService.asResource(content);
        } else {
            resource = fileService.loadResource(file);
        }

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(file.getContentType()))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + file.getOriginalFilename() + "\"")
                .body(resource);
    }
}
