# 🔗 Hunterrock GO

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
- 📝 Detaylı aktivite logları

## 🚀 Kurulum

```bash
# Projeyi indirin
git clone https://github.com/hunterrockmedya/hunterrock-go.git
cd hunterrock-go

# Bağımlılıkları yükleyin
npm install

# Kurulum sihirbazını çalıştırın
npm run setup
# → Admin kullanıcı adı, şifre, domain ve port sorulur
# → .env dosyası otomatik oluşturulur
# → Admin kullanıcısı veritabanına yazılır

# Başlatın
npm start
```

## 📘 Kullanım

1. `npm run setup` ile admin bilgileri, domain ve port'u girin
2. `npm start` ile sunucuyu başlatın
3. Tarayıcıda `siteniz.com/hradmin` adresine gidin
4. Kurulumda belirlediğiniz bilgilerle giriş yapın
5. "Linkler" sayfasından yeni link ekleyin

## 🛠️ Teknolojiler

- **Backend:** Node.js, Express.js
- **Database:** SQLite
- **Template:** EJS
- **Frontend:** HTML, CSS, JavaScript

## 📁 Dosya Yapısı

```
├── setup.js         # Kurulum sihirbazı
├── server.js        # Ana uygulama
├── views/           # EJS şablonları
├── public/css/      # Stiller
├── .env             # Ayarlar (setup.js ile oluşturulur)
└── hrgo.db          # Veritabanı (setup.js ile oluşturulur)
```

## ⚙️ Ortam Değişkenleri

> Bu değişkenler `npm run setup` ile otomatik oluşturulur.

| Değişken | Açıklama |
|----------|----------|
| `PORT` | Sunucu portu |
| `ADMIN_USERNAME` | Admin kullanıcı adı |
| `SESSION_SECRET` | Oturum güvenlik anahtarı (otomatik üretilir) |
| `DOMAIN` | Site domain'i |
| `DEFAULT_REDIRECT` | Varsayılan yönlendirme URL'si |

## 📜 Lisans

MIT License - Serbestçe kullanabilir, değiştirebilir ve dağıtabilirsiniz.

---

Made with ❤️ by [Hunterrock](https://hunterrockmedya.com)
