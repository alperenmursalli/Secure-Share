package org.example.secshare.vuln.process;

import org.example.secshare.vuln.VulnProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * VULN modulu: yuklenen dosyayi "arsivle" (zip).
 *  - vuln.process.cmd-injection=true  -> filename kabuga birlestirilir
 *    (sh -c "zip ... " + filename) -> command injection / RCE.
 *    ornek: {"filename":"x; cat <path>/master-keys.txt"}
 *  - false -> ProcessBuilder arg dizisi (kabuk yok), metakarakterler literal.
 *
 * SADECE YETKILI PENTEST / EGITIM ORTAMI ICIN.
 */
@RestController
@RequestMapping("/api/files")
public class ArchiveController {

    private final VulnProperties vuln;
    private final String storageBasePath;

    public ArchiveController(VulnProperties vuln,
                             @Value("${app.storage.base-path:uploads}") String storageBasePath) {
        this.vuln = vuln;
        this.storageBasePath = storageBasePath;
    }

    public record ArchiveRequest(String filename) {}

    @PostMapping("/archive")
    public ResponseEntity<String> archive(@RequestBody ArchiveRequest request) {
        String filename = request.filename();
        if (filename == null || filename.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "filename gerekli");
        }

        boolean cmdInjection = vuln.isEnabled() && vuln.getProcess().isCmdInjection();
        File workDir = new File(storageBasePath);

        try {
            Process process;
            if (cmdInjection) {
                // VULN: kullanici girdisi kabuk komutuna birlestiriliyor
                String cmd = "zip -q archive.zip " + filename;
                process = new ProcessBuilder("sh", "-c", cmd)
                        .directory(workDir)
                        .redirectErrorStream(true)
                        .start();
            } else {
                // Guvenli: kabuk yok, arg dizisi -> metakarakterler literal
                process = new ProcessBuilder("zip", "-q", "archive.zip", filename)
                        .directory(workDir)
                        .redirectErrorStream(true)
                        .start();
            }

            byte[] out = process.getInputStream().readNBytes(64 * 1024);
            process.waitFor(10, TimeUnit.SECONDS);
            String output = new String(out, StandardCharsets.UTF_8);
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(output.isBlank() ? "(cikti yok, exit=" + process.exitValue() + ")" : output);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Arsivleme hatasi: " + e.getMessage());
        }
    }

    /**
     * Zip Slip: yuklenen zip'in entry adlari dogrulanmadan cikartilir.
     *  - vuln.process.zip-slip=true  -> "../" iceren entry depo disina yazar.
     *  - false -> hedef yolun depo icinde kaldigi dogrulanir.
     */
    @PostMapping("/extract")
    public ResponseEntity<List<String>> extract(@RequestParam("file") MultipartFile file) {
        boolean zipSlip = vuln.isEnabled() && vuln.getProcess().isZipSlip();
        Path base = Paths.get(storageBasePath).toAbsolutePath().normalize();
        List<String> written = new ArrayList<>();

        try {
            Files.createDirectories(base);
            try (ZipInputStream zis = new ZipInputStream(file.getInputStream())) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.isDirectory()) {
                        continue;
                    }
                    Path target;
                    if (zipSlip) {
                        // VULN: entry adi dogrulanmadan resolve ediliyor
                        target = base.resolve(entry.getName());
                    } else {
                        target = base.resolve(entry.getName()).normalize();
                        if (!target.startsWith(base)) {
                            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                    "Zip Slip engellendi: " + entry.getName());
                        }
                    }
                    if (target.getParent() != null) {
                        Files.createDirectories(target.getParent());
                    }
                    Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
                    written.add(target.toString());
                }
            }
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Extract hatasi: " + e.getMessage());
        }
        return ResponseEntity.ok(written);
    }
}
