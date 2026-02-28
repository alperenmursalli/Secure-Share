# Render'a Deploy Etme Rehberi

## Önemli Notlar

### Veritabanı
- Render otomatik olarak PostgreSQL veritabanı oluşturur
- `render.yaml` dosyasındaki database ayarları otomatik bağlantı sağlar
- Veritabanı bağlantı bilgileri environment variables olarak otomatik ayarlanır

### Dosya Depolama
- Render'da dosya sistemi **geçici**dir (uygulama yeniden başladığında silinir)
- Production için **S3** veya benzeri bir servis kullanman önerilir
- Şimdilik `/opt/render/project/src/uploads` kullanılıyor (geçici)

## Adım Adım Deploy

### 1. GitHub'a Push Et
```bash
git add .
git commit -m "Render deploy hazırlığı"
git push origin main
```

### 2. Render'da Yeni Servis Oluştur

1. [Render Dashboard](https://dashboard.render.com) → New → Web Service
2. GitHub repo'nu bağla
3. Ayarlar:
   - **Name**: secshare
   - **Environment**: Java
   - **Build Command**: `./mvnw clean package -DskipTests`
   - **Start Command**: `java -jar target/secshare-0.0.1-SNAPSHOT.jar`
   - **Plan**: Free (veya istediğin plan)

### 3. PostgreSQL Veritabanı Ekle

1. Render Dashboard → New → PostgreSQL
2. Ayarlar:
   - **Name**: secshare-db
   - **Database Name**: secshare
   - **User**: secshare_user
   - **Plan**: Free
3. Web Service'e bağla (Internal Database URL)

### 4. Environment Variables Ayarla

Render Dashboard → Environment sekmesinde şunları ekle:

```
JWT_SECRET=<güçlü bir base64 secret>
STORAGE_PATH=/opt/render/project/src/uploads
PORT=8080
```

**JWT_SECRET oluşturma:**
```bash
# Terminal'de:
openssl rand -base64 32
```

### 5. Deploy

Render otomatik olarak deploy edecek. Logları kontrol et.

## Production İçin Öneriler

### Dosya Depolama (Önemli!)

Render'da dosya sistemi geçici olduğu için:

1. **AWS S3** kullan (önerilen)
2. **Cloudinary** kullan
3. **Render Persistent Disk** kullan (ücretli plan gerekir)

### S3 Entegrasyonu (İsteğe Bağlı)

Eğer S3 kullanmak istersen, `FileService`'i güncellemen gerekir.

## Test Etme

Deploy sonrası:
- `https://secshare.onrender.com/test.html` - Test sayfası
- `https://secshare.onrender.com/api/auth/register` - Kayıt
- `https://secshare.onrender.com/api/auth/login` - Giriş

## Sorun Giderme

### Veritabanı Bağlantı Hatası
- Environment variables'ı kontrol et
- Database'in web service'e bağlı olduğundan emin ol

### Dosya Yükleme Hatası
- Storage path'in yazılabilir olduğundan emin ol
- Production'da S3 kullan

### Port Hatası
- Render otomatik PORT sağlar, değiştirme
