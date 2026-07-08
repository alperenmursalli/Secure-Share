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
import static org.example.secshare.vuln.ExploitHelpers.*;

/**
 * Ayni ortam ama vuln.enabled=false: tum bayraklar kapali. Zincirin her adimi
 * bloklanmali. Bu, "before/after" ogretimini ve regresyon korumasini saglar.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "vuln.enabled=false"
)
@ActiveProfiles("vuln")
class SecureModeIT {

    @Autowired
    TestRestTemplate rest;

    @LocalServerPort
    int port;

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void enumerationIsGeneric() {
        // yok kullanici da yanlis sifre de ayni: 401 (404 sizdirmaz)
        assertThat(login(rest, base(), "nobody@corp.local", "x").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(login(rest, base(), "alice@corp.local", "wrong").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void massAssignmentIgnored() {
        String email = "sec-" + System.nanoTime() + "@evil.com";
        register(rest, base(), email, "password1", "ADMIN");
        String token = loginToken(rest, base(), email, "password1");
        // rol yok sayilmali -> ADMIN ucuna erisememeli
        assertThat(get(rest, base() + "/api/files/all", token).getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void forgedTokenRejected() {
        // zayif secret kapali -> forge edilen imza gecersiz
        HttpStatus s = (HttpStatus) get(rest, base() + "/api/files/all", forgeAdminToken()).getStatusCode();
        assertThat(s.is4xxClientError()).isTrue();
        assertThat(s).isNotEqualTo(HttpStatus.OK);
    }

    @Test
    void idorBlocked() {
        String alice = loginToken(rest, base(), "alice@corp.local", "Summer2024!");
        String mine = get(rest, base() + "/api/files", alice).getBody();
        String aliceFile = fileIdByName(mine, "salary.pdf");
        assertThat(aliceFile).isNotNull();

        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        assertThat(get(rest, base() + "/api/files/legacy/" + aliceFile, bob).getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void sqlInjectionNeutralized() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        String payload = "zzz%' UNION SELECT email || ':' || password_hash FROM users -- ";
        ResponseEntity<String> r = rest.exchange(
                base() + "/api/files/search?name={n}", org.springframework.http.HttpMethod.GET,
                new org.springframework.http.HttpEntity<>(bearer(bob)), String.class, payload);
        // parametreli sorgu -> hash sizmaz
        assertThat(r.getBody()).doesNotContain("$2a$");
    }

    @Test
    void pathTraversalBlocked() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        assertThat(get(rest, base() + "/api/files/raw?path=/etc/passwd", bob).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void ssrfBlocked() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        String json = "{\"url\":\"http://127.0.0.1:" + port + "/actuator/health\"}";
        assertThat(postJson(rest, base() + "/api/files/import", bob, json).getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void yamlSafeConstructorRejectsGadget() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        assertThat(postBody(rest, base() + "/api/files/import/yaml", bob,
                MediaType.TEXT_PLAIN, "!!java.util.Date []").getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void viewServedSafely() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        byte[] payload = "<script>alert(1)</script>".getBytes();
        String up = uploadFile(rest, base() + "/api/files/upload", bob, "x.txt", MediaType.TEXT_HTML, payload).getBody();
        String id = up.replaceAll(".*\"id\":\"([^\"]+)\".*", "$1");
        ResponseEntity<String> r = get(rest, base() + "/api/files/view/" + id, null);
        assertThat(r.getHeaders().getContentType().toString()).contains("application/octet-stream");
        assertThat(r.getHeaders().getFirst("Content-Disposition")).contains("attachment");
    }

    @Test
    void commandInjectionNeutralized() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        ResponseEntity<String> r = postJson(rest, base() + "/api/files/archive", bob,
                "{\"filename\":\"x; echo SHOULD_NOT_RUN\"}");
        assertThat(r.getBody()).doesNotContain("SHOULD_NOT_RUN");
    }

    @Test
    void zipSlipBlocked() {
        String bob = loginToken(rest, base(), "bob@corp.local", "password123");
        byte[] zip = makeZip(Map.of("../zipslip_secure.txt", "x"));
        assertThat(uploadFile(rest, base() + "/api/files/extract", bob,
                "evil.zip", MediaType.APPLICATION_OCTET_STREAM, zip).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
