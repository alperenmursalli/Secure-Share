package org.example.secshare.file;

import org.example.secshare.auth.security.UserPrincipal;
import org.example.secshare.file.dto.FileInfoResponse;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping("/upload")
    public FileInfoResponse upload(
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserPrincipal user
    ) {
        return fileService.upload(file, user);
    }
    

    @GetMapping
    public List<FileInfoResponse> listMyFiles(
            @AuthenticationPrincipal UserPrincipal user
    ) {
        return fileService.listMyFiles(user);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Resource> download(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal UserPrincipal user
    ) {
        Resource resource = fileService.loadFile(id, user);

        String contentType = fileService.getContentType(id, user);
        String originalFilename = fileService.getOriginalFilename(id, user);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + originalFilename + "\"")
                .body(resource);
    }
    @GetMapping("/all")
    public List<FileInfoResponse> listAllFiles() {
        return fileService.listAllFiles();
}

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(
            @PathVariable("id") UUID id,
            @AuthenticationPrincipal UserPrincipal user
    ) {
        fileService.delete(id, user);
        return ResponseEntity.noContent().build();
    }
}

