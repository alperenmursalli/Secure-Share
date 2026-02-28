# Render Docker Ayarları - Detaylı Rehber

## Docker Kullanırken Ayarlar

### Build & Deploy Sekmesi

**Environment**: `Docker` seç

**Build Command**: 
- ❌ **BOŞ BIRAK** veya hiç ekleme
- Dockerfile otomatik build yapar

**Start Command**: 
- ❌ **BOŞ BIRAK** veya hiç ekleme  
- Dockerfile'daki `ENTRYPOINT` kullanılır

**Dockerfile Path**: `./Dockerfile`
- Otomatik bulur, değiştirme gerekmez

**Docker Build Context Directory**: `.`
- Root directory, değiştirme gerekmez

### Health Check

**Health Check Path**: `/healthz` veya `/health`
- Her ikisi de çalışır
- Render düzenli olarak bu endpoint'e istek atar
- Başarılı olursa servis "healthy" olarak işaretlenir

### Registry Credential

**Registry Credential**: `No credential`
- Public Docker image kullanıyorsan gerekmez
- Private registry kullanıyorsan credential ekle

## Dockerfile Nasıl Çalışıyor?

```dockerfile
# Stage 1: Build
FROM eclipse-temurin:17-jdk-alpine AS build
# Maven ile JAR oluşturulur

# Stage 2: Runtime  
FROM eclipse-temurin:17-jre-alpine
# Sadece JRE ile minimal image
# ENTRYPOINT: java -jar app.jar
```

**Build süreci:**
1. Maven dependencies indirilir
2. Kod compile edilir
3. JAR dosyası oluşturulur
4. Runtime image'e kopyalanır
5. Container başlatılır

## Environment Variables

**Otomatik eklenenler:**
- `DATABASE_URL` (PostgreSQL'den)
- `DB_USERNAME` (PostgreSQL'den)
- `DB_PASSWORD` (PostgreSQL'den)
- `PORT` (Render otomatik sağlar)

**Manuel eklemen gerekenler:**
- `JWT_SECRET` (zorunlu)
- `STORAGE_PATH` (opsiyonel)

## Özet - Render Ayarları

### Build & Deploy
- ✅ Environment: **Docker**
- ✅ Build Command: **BOŞ** (Dockerfile kullanır)
- ✅ Start Command: **BOŞ** (Dockerfile kullanır)
- ✅ Dockerfile Path: `./Dockerfile`
- ✅ Docker Build Context: `.`

### Health Check
- ✅ Health Check Path: `/healthz` veya `/health`

### Registry
- ✅ Registry Credential: `No credential`

## Java Environment Kullanırsan (Alternatif)

Eğer Docker yerine Java environment seçersen:

**Build Command**: `./mvnw clean package -DskipTests`

**Start Command**: `java -jar target/secshare-0.0.1-SNAPSHOT.jar`

Ama Docker önerilir çünkü daha kontrollü.
