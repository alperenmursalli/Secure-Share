# SecShare — Vulnerable Mode

> ⚠️ **UYARI:** Bu profil **bilerek güvensizdir**. Yalnızca **yetkili pentest / eğitim**
> ortamında, **izole** bir makinede çalıştırın. **İnternete açık deploy ETMEYİN.**
> `main` / varsayılan profil güvenlidir; zafiyetler yalnızca `vuln` profilinde ve
> ilgili bayrak açıkken devrededir.

## Çalıştırma

```bash
# H2 in-memory (Docker/Postgres gerekmez) + tüm zafiyet bayrakları açık
SPRING_PROFILES_ACTIVE=vuln ./mvnw spring-boot:run
```

Uygulama `http://localhost:8080` üzerinde açılır. Açılışta seed verisi loglanır.

### Docker Compose (izole + iç SSRF hedefi)

```bash
docker compose -f docker-compose.vuln.yml up --build
```

`internal` servisi host'a **açılmaz** (yalnızca `expose`); sadece `app`
konteynerinden erişilir. Bu yüzden iç secret'a ulaşmanın tek yolu app
üzerindeki **SSRF** açığıdır:

```bash
curl -s -X POST localhost:8080/api/files/import -H "Authorization: Bearer $USER_JWT" \
  -H 'Content-Type: application/json' -d '{"url":"http://internal/secret"}'
# -> FLAG{ssrf_reached_internal_service}
```

## Testler (exploit + secure-mod doğrulaması)

```bash
./mvnw test
```

- `VulnChainIT` — her açığın gerçekten sömürülebildiğini kanıtlar.
- `SecureModeIT` — `vuln.enabled=false` iken her adımın bloklandığını doğrular.

Bu ikisi hem regresyon koruması hem de canlı exploit referansıdır.

## Seed Hesaplar

| Email | Şifre | Rol | Not |
|-------|-------|-----|-----|
| `alice@corp.local` | `Summer2024!` | USER | zayıf şifre (brute force) |
| `bob@corp.local` | `password123` | USER | zayıf şifre; dosyasında SSRF ipucu |
| `admin@secshare.local` | *(güçlü)* | ADMIN | login ile erişilemez → JWT forge |

## Zafiyet Bayrakları

Tümü `src/main/resources/application-vuln.properties` içinde. Bir açığı kapatmak için
`false` yapın; **hepsi `false` iken uygulama güvenli davranır** (before/after eğitimi).

| Bayrak | Açık | OWASP |
|--------|------|-------|
| `vuln.jwt.weak-secret` | Bilinen zayıf HMAC secret → JWT forge | A02 |
| `vuln.jwt.allow-none` | `alg:none` kabulü | A02 |
| `vuln.auth.user-enum` | Kullanıcı enumeration | A07 |
| `vuln.auth.no-rate-limit` | Brute force (rate limit yok) | A07 |
| `vuln.auth.mass-assignment` | register `roles` ile privesc | A01/A08 |
| `vuln.access.legacy-download` | IDOR indirme | A01 |
| `vuln.search.sqli` | SQL injection | A03 |
| `vuln.file.path-traversal` | Path traversal / LFI | A01/A05 |
| `vuln.import.ssrf` | SSRF | A10 |
| `vuln.import.xxe` | XXE | A05 |
| `vuln.import.yaml` | SnakeYAML unsafe load (CVE-2022-1471) | A06/A08 |
| `vuln.process.cmd-injection` | Command injection / RCE | A03 |
| `vuln.process.zip-slip` | Zip Slip (depo dışına yazma) | A01 |
| `vuln.serve.stored-xss` | Stored XSS | A03 |
| `vuln.cors.wildcard` | CORS misconfiguration | A05 |
| `vuln.errors.verbose` | Bilgi sızıntısı | A05 |

Ek olarak (config ile): `/actuator/*` açık — `/actuator/env` (secret sızıntısı) ve
`/actuator/heapdump` (bellekten credential çıkarma) recon için kullanılabilir.
`org.yaml:snakeyaml:1.33` bilerek zafiyetli pinlenmiştir (SCA taraması pratiği).

## Dokümanlar
- `docs/CHALLENGES.md` — kursiyer için görevler ve ipuçları (spoiler yok)
- `docs/SOLUTIONS.md` — eğitmen için tam exploit adımları (**spoiler**)
