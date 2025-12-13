# 🔗 HunterRock GO

Kendi sunucunuzda çalışan modern URL kısaltma ve link yönetim sistemi.

## 📌 Nedir?

Kısa ve akılda kalıcı linkler oluşturmanızı sağlayan bir URL yönlendirme sistemidir.

**Örnek:** `go.siteniz.com/instagram` → `instagram.com/profiliniz`

## ✨ Özellikler

- 🔗 Özel kısa linkler oluşturma
- 📊 Tıklama istatistikleri
- 👥 Çoklu kullanıcı desteği
- 📱 Mobil uyumlu admin paneli
- 🔐 Güvenli oturum yönetimi
- � Detaylı aktivite logları

## � Kurulum

```bash
# Projeyi indirin
git clone https://github.com/user/hunterrock-go.git
cd hunterrock-go

# Bağımlılıkları yükleyin
npm install

# Ortam dosyasını oluşturun
cp .env.example .env

# .env dosyasını düzenleyin
# ADMIN_USERNAME, ADMIN_PASSWORD, SESSION_SECRET değerlerini değiştirin

# Başlatın
npm start
```

## � Kullanım

1. Tarayıcıda `http://localhost:3000/hradmin` adresine gidin
2. `.env` dosyasındaki kullanıcı adı ve şifre ile giriş yapın
3. "Linkler" sayfasından yeni link ekleyin
4. Kısa linkiniz hazır: `http://localhost:3000/slug`

## 🛠️ Teknolojiler

- **Backend:** Node.js, Express.js
- **Database:** SQLite
- **Template:** EJS
- **Frontend:** HTML, CSS, JavaScript

## � Dosya Yapısı

```
├── server.js        # Ana uygulama
├── views/           # EJS şablonları
├── public/css/      # Stiller
├── .env             # Ayarlar (git'e dahil değil)
└── hrgo.db          # Veritabanı (git'e dahil değil)
```

## ⚙️ Ortam Değişkenleri

| Değişken | Açıklama |
|----------|----------|
| `PORT` | Sunucu portu |
| `ADMIN_USERNAME` | Admin kullanıcı adı |
| `ADMIN_PASSWORD` | Admin şifresi |
| `SESSION_SECRET` | Oturum güvenlik anahtarı |
| `DEFAULT_REDIRECT` | Varsayılan yönlendirme URL'si |

## � Lisans

MIT License - Serbestçe kullanabilir, değiştirebilir ve dağıtabilirsiniz.

---

Made with ❤️ by [HunterRock Medya](https://hunterrockmedya.com)
