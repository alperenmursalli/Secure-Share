package org.example.secshare.file;

import org.example.secshare.auth.security.UserPrincipal;
import org.example.secshare.file.dto.FileInfoResponse;
import org.example.secshare.user.User;
import org.example.secshare.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
public class FileService {

    private static final long MAX_FILE_SIZE_BYTES = 50L * 1024 * 1024; // 50 MB
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
            "pdf", "png", "jpg", "jpeg", "txt", "doc", "docx", "xlsx", "zip"
    );

    private final SharedFileRepository sharedFileRepository;
    private final UserRepository userRepository;
    private final Path baseStoragePath;

    public FileService(
            SharedFileRepository sharedFileRepository,
            UserRepository userRepository,
            // Fly için default'u /tmp/uploads yaptık
            @Value("${app.storage.base-path:/tmp/uploads}") String basePath
    ) {
        this.sharedFileRepository = sharedFileRepository;
        this.userRepository = userRepository;
        this.baseStoragePath = Paths.get(basePath).toAbsolutePath().normalize();

        try {
            Files.createDirectories(this.baseStoragePath);
        } catch (IOException e) {
            throw new IllegalStateException("Could not create storage directory: " + this.baseStoragePath, e);
        }
    }

    public FileInfoResponse upload(MultipartFile file, UserPrincipal principal) {
        if (file == null || file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Dosya boş olamaz");
        }

        if (file.getSize() > MAX_FILE_SIZE_BYTES) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "Dosya boyutu çok büyük (max 50MB)");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.isBlank()) {
            originalFilename = "file";
        }

        String extension = getExtension(originalFilename);
        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bu dosya türüne izin verilmiyor");
        }

        UUID fileId = UUID.randomUUID();
        String storageFilename = fileId + (extension.isEmpty() ? "" : "." + extension);

        Path targetPath = baseStoragePath.resolve(storageFilename).normalize();
        if (!targetPath.startsWith(baseStoragePath)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Geçersiz dosya adı");
        }

        try {
            Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Dosya kaydedilemedi");
        }

        User owner = userRepository.findById(principal.userId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        SharedFile sharedFile = new SharedFile();
        sharedFile.setId(fileId);
        sharedFile.setOwner(owner);
        sharedFile.setOriginalFilename(originalFilename);
        sharedFile.setStorageFilename(storageFilename);
        sharedFile.setContentType(file.getContentType() != null ? file.getContentType() : "application/octet-stream");
        sharedFile.setSizeBytes(file.getSize());
        sharedFile.setCreatedAt(Instant.now());
        sharedFile.setDeleted(false);

        sharedFileRepository.save(sharedFile);

        return toResponse(sharedFile);
    }

    public List<FileInfoResponse> listMyFiles(UserPrincipal principal) {
        User owner = userRepository.findById(principal.userId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        return sharedFileRepository.findByOwnerAndDeletedFalseOrderByCreatedAtDesc(owner)
                .stream()
                .map(this::toResponse)
                .toList();
    }

    public Resource loadFile(UUID fileId, UserPrincipal principal) {
        SharedFile sharedFile = getOwnedFileOrThrow(fileId, principal);

        Path filePath = baseStoragePath.resolve(sharedFile.getStorageFilename()).normalize();
        try {
            Resource resource = new UrlResource(filePath.toUri());
            if (!resource.exists() || !resource.isReadable()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Dosya bulunamadı");
            }
            return resource;
        } catch (MalformedURLException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Dosya okunamadı");
        }
    }

    public SharedFile getOwnedFileOrThrow(UUID fileId, UserPrincipal principal) {
        SharedFile sharedFile = sharedFileRepository.findByIdAndDeletedFalse(fileId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Dosya bulunamadı"));

        if (!sharedFile.getOwner().getId().equals(principal.userId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Bu dosyaya erişim yetkiniz yok");
        }

        return sharedFile;
    }

    public void delete(UUID fileId, UserPrincipal principal) {
        SharedFile sharedFile = getOwnedFileOrThrow(fileId, principal);
        sharedFile.setDeleted(true);
        sharedFileRepository.save(sharedFile);

        Path filePath = baseStoragePath.resolve(sharedFile.getStorageFilename()).normalize();
        try {
            Files.deleteIfExists(filePath);
        } catch (IOException ignored) {
        }
    }

    public String getContentType(UUID fileId, UserPrincipal principal) {
        return getOwnedFileOrThrow(fileId, principal).getContentType();
    }

    public String getOriginalFilename(UUID fileId, UserPrincipal principal) {
        return getOwnedFileOrThrow(fileId, principal).getOriginalFilename();
    }

    private FileInfoResponse toResponse(SharedFile file) {
        return new FileInfoResponse(
                file.getId(),
                file.getOriginalFilename(),
                file.getSizeBytes(),
                file.getContentType(),
                file.getCreatedAt()
        );
    }

    private String getExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        if (lastDot == -1 || lastDot == filename.length() - 1) {
            return "";
        }
        return filename.substring(lastDot + 1);
    }
}