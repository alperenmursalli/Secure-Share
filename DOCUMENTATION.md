# SecShare — Dokümantasyon & Kullanım Kılavuzu

SecShare, kullanıcıların kayıt olup giriş yaptıktan sonra dosya yükleyip
yönetebildiği, **JWT tabanlı kimlik doğrulamaya** sahip bir dosya paylaşım
uygulamasıdır. Backend Spring Boot (Java 17), veritabanı PostgreSQL, dosyalar
sunucunun diskinde saklanır.

> ⚠️ **Güvenlik notu:** Bu uygulama eğitim/güvenlik test amaçlı geliştirilmiştir.
> Halka açık internette çalıştırırken dikkatli ol; hassas veri koyma ve erişimi
> kısıtla.

---

## 1. Uygulama nasıl çalışıyor?

### Mimari

```
Tarayıcı / curl
      │  (HTTP + JWT Bearer token)
      ▼
┌─────────────────────────────┐
│  Spring Boot (port 8080)    │
│  ├─ AuthController  /api/auth│  → kayıt & giriş, token üretir
│  ├─ FileController  /api/files│ → yükleme, listeleme, indirme, silme
│  ├─ JWT filtresi             │  → her istekte token'ı doğrular
│  └─ Statik sayfalar          │  → files.html, test.html
└──────────┬──────────┬────────┘
           │          │
     ┌─────▼────┐  ┌──▼─────────────┐
     │PostgreSQL│  │ Disk: /app/uploads │
     │ users,   │  │ (yüklenen dosyalar)│
     │ files    │  └────────────────────┘
     └──────────┘
```

### Kimlik doğrulama akışı (JWT)

1. Kullanıcı `/api/auth/register` ile kayıt olur. Şifre **BCrypt** ile
   hash'lenip `users` tablosuna yazılır.
2. `/api/auth/login` ile giriş yapar; doğruysa bir **JWT access token** döner.
3. Sonraki tüm korumalı isteklerde bu token `Authorization: Bearer <token>`
   başlığıyla gönderilir.
4. `JwtAuthenticationFilter` her istekte token'ı doğrular; geçerliyse istek
   sahibi (kullanıcı) belirlenir. Token varsayılan olarak **60 dakika** geçerlidir.

Token içinde kullanıcı id'si (`subject`), `email` ve `roles` bilgisi bulunur.
Oturum sunucuda tutulmaz (**stateless**) — kimlik tamamen token'dan gelir.

### Dosya saklama

- Yüklenen dosya diske `<uuid>.<uzantı>` adıyla kaydedilir (çakışma olmaz).
- Orijinal ad, boyut, tip ve sahip bilgisi `files` tablosunda tutulur.
- Bir dosyayı **yalnızca sahibi** indirebilir/silebilir. Başkasının dosyasına
  erişim `403 Forbidden` döner.
- Silme işlemi **soft-delete**'tir (kayıt `deleted=true` yapılır) ve dosya
  diskten de silinir.

### Kısıtlar

| Kural | Değer |
|-------|-------|
| Maksimum dosya boyutu | 50 MB |
| İzin verilen uzantılar | `pdf, png, jpg, jpeg, txt, doc, docx, xlsx, zip` |
| Şifre uzunluğu | 8–72 karakter |
| Token ömrü | 60 dakika (varsayılan) |

---

## 2. Nasıl çalıştırırım? (Docker ile)

Ön koşul: Docker + docker-compose kurulu olmalı.

```bash
# 1) Ortam değişkenlerini hazırla
cp .env.example .env
# .env içine güçlü bir DB_PASSWORD ve JWT_SECRET yaz.
# JWT secret üretmek için:  openssl rand -base64 32

# 2) App + PostgreSQL'i birlikte başlat
docker-compose up -d --build

# 3) Logları izle
docker-compose logs -f app
```

"Started SecshareApplication" satırını görünce hazırdır.

Tarayıcıda aç:
- **http://localhost:8080/test.html** — hızlı test arayüzü
- **http://localhost:8080/files.html** — dosya yönetim arayüzü

Yönetim komutları:

```bash
docker-compose ps                # durum
docker-compose down              # durdur (veriler kalır)
docker-compose down -v           # durdur + DB & dosyaları sil
docker-compose up -d --build     # kod değişince yeniden başlat
```

---

## 3. Nasıl denerim? (adım adım — curl)

Aşağıdaki komutları sırayla terminalde çalıştırabilirsin.

### 3.1 Kayıt ol

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"password123"}'
```
Başarılı → `201 Created`. Aynı email tekrar → `409 Conflict`.

### 3.2 Giriş yap ve token al

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"demo@example.com","password":"password123"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["accessToken"])')

echo $TOKEN
```

### 3.3 Kimliği doğrula (test endpoint'i)

```bash
curl http://localhost:8080/hello -H "Authorization: Bearer $TOKEN"
# → Hello demo@example.com
```

### 3.4 Dosya yükle

```bash
echo "merhaba secshare" > sample.txt

curl -X POST http://localhost:8080/api/files/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample.txt"
# → {"id":"...","name":"sample.txt","sizeBytes":17,...}
```
Dönen `id`'yi not al.

### 3.5 Dosyalarını listele

```bash
curl http://localhost:8080/api/files -H "Authorization: Bearer $TOKEN"
```

### 3.6 Dosya indir

```bash
curl http://localhost:8080/api/files/<FILE_ID> \
  -H "Authorization: Bearer $TOKEN" -O -J
```

### 3.7 Dosya sil

```bash
curl -X DELETE http://localhost:8080/api/files/<FILE_ID> \
  -H "Authorization: Bearer $TOKEN"
# → 204 No Content
```

### 3.8 Token'sız erişim denemesi

```bash
curl -i http://localhost:8080/api/files
# → 403 (kimlik doğrulanmadı)
```

---

## 4. API Referansı

Taban URL: `http://localhost:8080`

| Metot | Yol | Auth | Açıklama |
|-------|-----|------|----------|
| POST | `/api/auth/register` | ✗ | Kayıt. Body: `{email, password}`. → 201 |
| POST | `/api/auth/login` | ✗ | Giriş. Body: `{email, password}`. → `{accessToken}` |
| GET | `/hello` | ✓ | Kimlik testi. → `Hello <email>` |
| POST | `/api/files/upload` | ✓ | Multipart `file` alanı ile yükleme. → dosya bilgisi |
| GET | `/api/files` | ✓ | Kendi dosyalarını listele |
| GET | `/api/files/{id}` | ✓ | Dosya indir (yalnızca sahibi) |
| DELETE | `/api/files/{id}` | ✓ | Dosya sil (yalnızca sahibi). → 204 |
| GET | `/api/files/all` | ✓ ADMIN | Tüm dosyalar (yalnızca ADMIN rolü) |
| GET | `/health`, `/healthz` | ✗ | Sağlık kontrolü. → `{"status":"ok"}` |

**Auth başlığı:** `Authorization: Bearer <accessToken>`

### İstek/yanıt gövdeleri

`RegisterRequest` / `LoginRequest`:
```json
{ "email": "demo@example.com", "password": "password123" }
```

`AuthResponse` (login yanıtı):
```json
{ "accessToken": "eyJhbGciOi..." }
```

`FileInfoResponse` (yükleme/listeleme):
```json
{
  "id": "9e56a43a-...",
  "name": "sample.txt",
  "sizeBytes": 17,
  "contentType": "text/plain",
  "createdAt": "2026-07-09T20:04:26Z"
}
```

### Sık karşılaşılan HTTP kodları

| Kod | Anlamı |
|-----|--------|
| 201 | Kayıt başarılı |
| 400 | Geçersiz istek (boş dosya, izinsiz uzantı, kısa şifre) |
| 401 | Hatalı email/şifre (login) |
| 403 | Token yok/geçersiz ya da başkasının dosyası |
| 409 | Email zaten kayıtlı |
| 413 | Dosya 50 MB'tan büyük |

---

## 5. Web arayüzü

- **`/test.html`** — token alıp basit istekleri denemek için hızlı test sayfası.
- **`/files.html`** — giriş yapıp dosya yükleme/listeleme/indirme yapılan arayüz.

Tarayıcıdan kullanmak için önce bu sayfalardan giriş yap; sayfa senin için token'ı
saklayıp isteklere ekler.

---

## 6. Yapılandırma (ortam değişkenleri)

`.env` (docker-compose tarafından okunur) ve uygulamanın desteklediği değişkenler:

| Değişken | Varsayılan | Açıklama |
|----------|-----------|----------|
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://db:5432/secshare` | Veritabanı adresi |
| `SPRING_DATASOURCE_USERNAME` | — | DB kullanıcısı (`DB_USER`) |
| `SPRING_DATASOURCE_PASSWORD` | — | DB şifresi (`DB_PASSWORD`) |
| `JWT_SECRET` | (dev default) | Base64, en az 32 byte olmalı |
| `JWT_EXPIRATION_MINUTES` | `60` | Token ömrü (dakika) |
| `STORAGE_PATH` | `/app/uploads` | Dosyaların saklandığı dizin |
| `PORT` | `8080` | HTTP portu |
| `LOG_LEVEL` | `INFO` | Spring Security log seviyesi |

> `JWT_SECRET` en az 32 byte (base64 çözülünce) olmalı, yoksa uygulama açılmaz.
> Üretmek için: `openssl rand -base64 32`

---

## 7. Sorun giderme

- **App açılmıyor / DB hatası:** `docker-compose logs app` ve `docker-compose logs db`
  ile bak. DB'nin `Up (healthy)` olmasını bekle — app, DB hazır olana kadar
  başlamaz.
- **`/` yolunda 404:** Normal, ana route yok. `/test.html` veya `/files.html` kullan.
- **Yükleme 400 dönüyor:** Uzantı izin listesinde mi? (`pdf, png, jpg, jpeg, txt,
  doc, docx, xlsx, zip`) ve dosya boş olmamalı.
- **İstek 403 dönüyor:** Token eksik/süresi dolmuş olabilir; tekrar login ol.
- **Port çakışması:** 8080 veya 5432 doluysa `docker-compose.yml`'deki port
  eşlemesini değiştir.

---

## 8. Teknoloji özeti

- **Backend:** Spring Boot 3.4.2, Java 17
- **Güvenlik:** Spring Security, JWT (jjwt 0.12.5), BCrypt (strength 12)
- **Veri:** Spring Data JPA + PostgreSQL 16
- **Depolama:** Yerel dosya sistemi (`/app/uploads`, Docker volume ile kalıcı)
- **Paketleme:** Docker (çok aşamalı build) + docker-compose
