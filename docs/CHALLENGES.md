# SecShare — Pentest Görevleri

Hedef: recon'dan RCE'ye giden bağlı bir zinciri tamamlamak. Her aşama bir sonrakinin
anahtarını verir. Base URL: `http://localhost:8080`.

> Çözümler `docs/SOLUTIONS.md` içinde (spoiler). Önce kendin dene.

---

### Aşama 0 — Recon (A05)
Uygulamanın açık yüzeyini haritalandır. Framework hangi yönetim/panel uçlarını
dışarı vermiş olabilir? Bir yerlerde uygulama sırları sızıyor olabilir.
**İpucu:** `/actuator`, `/h2-console`, statik `.html` sayfaları.

### Aşama 1 — Kullanıcı Enumeration + Brute Force (A07)
`/api/auth/register` ve `/api/auth/login` cevaplarını dikkatle karşılaştır. Var olan
ve olmayan e-postalar aynı mı cevaplanıyor? Geçerli bir e-posta bulduktan sonra
zayıf parolayı dene.
**Hedef:** geçerli bir USER JWT'si.

### Aşama 2 — JWT Privilege Escalation (A02)
Token nasıl imzalanmış? İmza anahtarı gerçekten gizli mi? Ele geçirdiğin bir sırla
kendi token'ını üretebilir misin — mesela `roles` claim'ini değiştirerek?
**Hedef:** `GET /api/files/all` (yalnızca ADMIN).

### Aşama 3 — IDOR (A01)
Dosya indirme uçlarının hepsi sahipliği kontrol ediyor mu? "Eski" bir uç nokta
gözden kaçmış olabilir. Başkasının dosya kimliğiyle ne olur?
**Hedef:** alice'in dosyasındaki flag.

### Aşama 4 — SQL Injection (A03)
Arama özelliği girdini nasıl işliyor? Tek tırnak ne yapıyor? `UNION` ile başka bir
tablodan veri çekebilir misin?
**Hedef:** `users` tablosundan e-posta + parola hash'leri.

### Aşama 5 — Path Traversal / LFI (A01/A05)
Ham dosya okuyan uç, verdiğin yolu doğruluyor mu? Depo dizininin dışına çıkabilir misin?
**Hedef:** uygulama config dosyasını / sunucudaki başka dosyaları oku.

### Aşama 6 — SSRF & XXE (A10/A05)
"URL'den içe aktar" özelliği sunucu adına istek atıyor. Nereye? XML kabul eden uç,
harici varlıkları (external entity) işliyor mu?
**Hedef:** iç servisleri/metadata'yı sunucu üzerinden çek; XXE ile yerel dosya oku.

### Aşama 7 — Stored XSS (A03)
Yüklenen dosya tarayıcıda nasıl servis ediliyor? Content-Type'ı sen kontrol
edebiliyor musun? Bir "view" linki JavaScript çalıştırabilir mi?
**Hedef:** kurbanın `localStorage` token'ını çalacak bir payload.

### Aşama 8 — Command Injection / RCE (A03) — Final
"Arşivle" özelliği dosya adını bir kabuk komutuna koyuyor. Araya kendi komutunu
sokabilir misin?
**Hedef:** `master-keys.txt` içindeki final flag + komut çalıştırma kanıtı (`id`).

---

## Ek Görevler

- **Mass Assignment (A01/A08):** Kayıt isteğine fazladan bir alan eklersen ne olur?
  Doğrudan admin olarak kaydolabilir misin?
- **Recon — Actuator (A05):** `/actuator/*` altında hangi hassas uçlar var? `env` ve
  `heapdump` sana ne verir?
- **Insecure Deserialization / SCA (A06/A08):** Bir "YAML içe aktar" ucu var. Parser
  hangi kütüphane, hangi sürüm? Bilinen bir CVE'si var mı? `!!` etiketleriyle ne yapılabilir?
- **Zip Slip (A01):** Yüklediğin zip'in içindeki dosya adlarını sen kontrol ediyorsun.
  Çıkartma dizininin dışına yazabilir misin?
- **SSRF pivot (A10):** docker-compose ortamında yalnızca iç ağdan erişilen bir servis var.
  Ona doğrudan ulaşamazsın — ama uygulama üzerinden?
