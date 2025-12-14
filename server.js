require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT;
const DOMAIN = process.env.DOMAIN;

// ============================================
// GÜVENLİK - Helmet (HTTP Headers)
// ============================================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
        },
    },
}));

// ============================================
// GÜVENLİK - Rate Limiting
// ============================================

// Genel rate limit
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 100, // IP başına 100 istek
    message: 'Çok fazla istek gönderdiniz, lütfen daha sonra tekrar deneyin.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Login için sıkı rate limit
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 5, // 5 giriş denemesi
    message: 'Çok fazla başarısız giriş denemesi. 15 dakika sonra tekrar deneyin.',
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // Başarılı girişleri sayma
});

app.use(generalLimiter);

// ============================================
// GÜVENLİK - Başarısız Giriş Loglama
// ============================================
const failedLogins = new Map(); // IP -> { count, lastAttempt }

function logFailedLogin(ip, username) {
    const now = Date.now();
    const record = failedLogins.get(ip) || { count: 0, attempts: [] };
    record.count++;
    record.attempts.push({ time: now, username });
    failedLogins.set(ip, record);

    console.log(`⚠️  Başarısız giriş: IP=${ip}, Kullanıcı=${username}, Deneme=${record.count}`);

    // 10'dan fazla başarısız deneme uyarısı
    if (record.count >= 10) {
        console.log(`🚨 UYARI: ${ip} adresinden ${record.count} başarısız giriş denemesi!`);
    }
}

function logSuccessfulLogin(ip, username) {
    // Başarılı girişte sayacı sıfırla
    failedLogins.delete(ip);
    console.log(`✅ Başarılı giriş: IP=${ip}, Kullanıcı=${username}`);
}

// IP alma helper
function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] ||
        req.headers['x-real-ip'] ||
        req.connection?.remoteAddress ||
        req.ip ||
        'unknown';
}

// ============================================
// DATABASE SETUP
// ============================================
const db = new sqlite3.Database(path.join(__dirname, 'hrgo.db'));

// Tabloları oluştur
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            target_url TEXT NOT NULL,
            title TEXT DEFAULT '',
            clicks INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_clicked_at DATETIME
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    `);

    // Users tablosu - Çoklu kullanıcı desteği
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    `);

    // Login/Logout log tablosu
    db.run(`
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username TEXT,
            action TEXT DEFAULT 'login',
            success INTEGER DEFAULT 0,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Detaylı click log tablosu
    db.run(`
        CREATE TABLE IF NOT EXISTS click_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link_id INTEGER,
            slug TEXT NOT NULL,
            target_url TEXT,
            ip TEXT NOT NULL,
            referer TEXT,
            user_agent TEXT,
            browser TEXT,
            browser_version TEXT,
            os TEXT,
            os_version TEXT,
            device_type TEXT,
            language TEXT,
            country TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (link_id) REFERENCES links(id)
        )
    `);

    // Aktivite log tablosu - Admin işlemleri
    db.run(`
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            category TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            target_name TEXT,
            details TEXT,
            ip TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Varsayılan ayarları ekle
    const defaultRedirect = process.env.DEFAULT_REDIRECT;
    const sessionSecret = process.env.SESSION_SECRET;

    db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('defaultRedirect', ?)`, [defaultRedirect]);
    db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('sessionSecret', ?)`, [sessionSecret]);

    // Varsayılan admin kullanıcısı oluştur (yoksa)
    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPassword = process.env.ADMIN_PASSWORD;

    db.get('SELECT id FROM users WHERE username = ?', [adminUsername], async (err, row) => {
        if (!row) {
            // İlk kullanıcıyı oluştur
            const bcrypt = require('bcryptjs');
            const hashedPassword = await bcrypt.hash(adminPassword, 12);
            db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                [adminUsername, hashedPassword, 'admin']);
            console.log(`👤 Varsayılan admin kullanıcısı oluşturuldu: ${adminUsername}`);
        }
    });
});

// Helper functions (Promise tabanlı)
function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

async function getSetting(key) {
    const row = await dbGet('SELECT value FROM settings WHERE key = ?', [key]);
    return row ? row.value : null;
}

async function setSetting(key, value) {
    await dbRun('UPDATE settings SET value = ? WHERE key = ?', [value, key]);
}

// Aktivite loglama fonksiyonu
async function logActivity(req, action, category, targetType = null, targetId = null, targetName = null, details = null) {
    try {
        const userId = req.session?.userId || null;
        const username = req.session?.username || 'Sistem';
        const ip = getClientIP(req);

        await dbRun(
            `INSERT INTO activity_logs (user_id, username, action, category, target_type, target_id, target_name, details, ip) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [userId, username, action, category, targetType, targetId, targetName, details, ip]
        );
    } catch (err) {
        console.error('Activity log error:', err);
    }
}

// Şifre hashleme/doğrulama
async function hashPassword(password) {
    return bcrypt.hash(password, 12);
}

// User-Agent parse fonksiyonu
function parseUserAgent(ua) {
    const result = {
        browser: 'Unknown',
        browserVersion: '',
        os: 'Unknown',
        osVersion: '',
        deviceType: 'Desktop'
    };

    if (!ua) return result;

    // Tarayıcı tespiti
    if (ua.includes('Firefox/')) {
        result.browser = 'Firefox';
        result.browserVersion = ua.match(/Firefox\/(\d+)/)?.[1] || '';
    } else if (ua.includes('Edg/')) {
        result.browser = 'Edge';
        result.browserVersion = ua.match(/Edg\/(\d+)/)?.[1] || '';
    } else if (ua.includes('Chrome/')) {
        result.browser = 'Chrome';
        result.browserVersion = ua.match(/Chrome\/(\d+)/)?.[1] || '';
    } else if (ua.includes('Safari/') && !ua.includes('Chrome')) {
        result.browser = 'Safari';
        result.browserVersion = ua.match(/Version\/(\d+)/)?.[1] || '';
    } else if (ua.includes('MSIE') || ua.includes('Trident/')) {
        result.browser = 'Internet Explorer';
        result.browserVersion = ua.match(/(?:MSIE |rv:)(\d+)/)?.[1] || '';
    } else if (ua.includes('Opera') || ua.includes('OPR/')) {
        result.browser = 'Opera';
        result.browserVersion = ua.match(/(?:Opera|OPR)\/(\d+)/)?.[1] || '';
    }

    // İşletim sistemi tespiti
    if (ua.includes('Windows NT 10')) {
        result.os = 'Windows';
        result.osVersion = '10/11';
    } else if (ua.includes('Windows NT 6.3')) {
        result.os = 'Windows';
        result.osVersion = '8.1';
    } else if (ua.includes('Windows NT 6.2')) {
        result.os = 'Windows';
        result.osVersion = '8';
    } else if (ua.includes('Windows NT 6.1')) {
        result.os = 'Windows';
        result.osVersion = '7';
    } else if (ua.includes('Mac OS X')) {
        result.os = 'macOS';
        result.osVersion = ua.match(/Mac OS X (\d+[._]\d+)/)?.[1]?.replace('_', '.') || '';
    } else if (ua.includes('Android')) {
        result.os = 'Android';
        result.osVersion = ua.match(/Android (\d+\.?\d*)/)?.[1] || '';
    } else if (ua.includes('iPhone') || ua.includes('iPad')) {
        result.os = 'iOS';
        result.osVersion = ua.match(/OS (\d+[._]\d+)/)?.[1]?.replace('_', '.') || '';
    } else if (ua.includes('Linux')) {
        result.os = 'Linux';
    }

    // Cihaz tipi tespiti
    if (ua.includes('Mobile') || ua.includes('Android') && !ua.includes('Tablet')) {
        result.deviceType = 'Mobile';
    } else if (ua.includes('iPad') || ua.includes('Tablet')) {
        result.deviceType = 'Tablet';
    } else if (ua.includes('Bot') || ua.includes('bot') || ua.includes('Crawler') || ua.includes('Spider')) {
        result.deviceType = 'Bot';
    }

    return result;
}

// URL doğrulama
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// Tehlikeli URL kontrolü
function isSafeUrl(url) {
    const dangerous = ['javascript:', 'data:', 'vbscript:', 'file:'];
    const lowerUrl = url.toLowerCase();
    return !dangerous.some(d => lowerUrl.startsWith(d));
}

// ============================================
// MIDDLEWARE
// ============================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session middleware (async init)
(async () => {
    // Sabit secret (sunucu bazlı)
    const serverSecret = crypto.randomBytes(32).toString('hex');

    app.use(session({
        secret: serverSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production', // Production --> HTTPS
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: 'strict' // CSRF koruması
        }
    }));

    // Auth middleware - kullanıcı token kontrolü
    function requireAuth(req, res, next) {
        if (req.session && req.session.isLoggedIn && req.session.userToken) {
            // Token doğrulama
            const expectedToken = crypto
                .createHmac('sha256', serverSecret)
                .update(req.session.username + req.session.loginTime)
                .digest('hex');

            if (req.session.userToken === expectedToken) {
                return next();
            }
        }
        // Geçersiz oturum - çıkış yap
        if (req.session) {
            req.session.destroy();
        }
        res.redirect('/hradmin/login');
    }

    // Admin only middleware
    function requireAdmin(req, res, next) {
        if (req.session && req.session.userRole === 'admin') {
            return next();
        }
        req.session.error = 'Bu sayfaya erişim yetkiniz yok';
        res.redirect('/hradmin');
    }

    // Flash messages + userRole
    app.use((req, res, next) => {
        if (req.session) {
            res.locals.success = req.session.success;
            res.locals.error = req.session.error;
            res.locals.userRole = req.session.userRole || 'user';
            res.locals.username = req.session.username || '';
            delete req.session.success;
            delete req.session.error;
        }
        next();
    });

    // ============================================
    // ANA SAYFA - API Status
    // ============================================
    app.get('/', (req, res) => {
        res.json({ message: 'Hunterrock - GO API Çalışıyor', status: 'online' });
    });

    // ============================================
    // ADMIN ROUTES
    // ============================================

    // Login sayfası
    app.get('/hradmin/login', (req, res) => {
        if (req.session && req.session.isLoggedIn) {
            return res.redirect('/hradmin');
        }
        res.render('login', { error: res.locals.error || null });
    });

    // Login işlemi (Rate limited)
    app.post('/hradmin/login', loginLimiter, async (req, res) => {
        const { username, password } = req.body;
        const clientIP = getClientIP(req);
        const userAgent = req.headers['user-agent'] || '';

        try {
            // Kullanıcıyı veritabanından bul
            const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);

            if (user) {
                // Şifre doğrulama
                const isValidPass = await bcrypt.compare(password, user.password);

                if (isValidPass) {
                    // Kullanıcıya özel benzersiz token oluştur
                    const loginTime = Date.now().toString();
                    const userToken = crypto
                        .createHmac('sha256', serverSecret)
                        .update(username + loginTime)
                        .digest('hex');

                    req.session.isLoggedIn = true;
                    req.session.userId = user.id;
                    req.session.username = username;
                    req.session.userRole = user.role;
                    req.session.loginTime = loginTime;
                    req.session.userToken = userToken;
                    req.session.clientIP = clientIP;

                    // Son giriş zamanını güncelle
                    await dbRun('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

                    // Başarılı giriş logla
                    logSuccessfulLogin(clientIP, username);
                    await dbRun('INSERT INTO login_logs (ip, username, action, success, user_agent) VALUES (?, ?, ?, 1, ?)', [clientIP, username, 'login', userAgent]);

                    return res.redirect('/hradmin');
                }
            }

            // Başarısız giriş
            logFailedLogin(clientIP, username || 'empty');
            await dbRun('INSERT INTO login_logs (ip, username, action, success, user_agent) VALUES (?, ?, ?, 0, ?)', [clientIP, username || 'empty', 'login', userAgent]);

            req.session.error = 'Hatalı kullanıcı adı veya şifre';
            res.redirect('/hradmin/login');
        } catch (err) {
            console.error('Login error:', err);
            req.session.error = 'Giriş sırasında bir hata oluştu';
            res.redirect('/hradmin/login');
        }
    });

    // Logout
    app.get('/hradmin/logout', async (req, res) => {
        const clientIP = getClientIP(req);
        const userAgent = req.headers['user-agent'] || '';

        if (req.session && req.session.username) {
            const username = req.session.username;
            console.log(`👋 Çıkış yapıldı: IP=${clientIP}, Kullanıcı=${username}`);

            // Çıkış logunu kaydet
            await dbRun(
                'INSERT INTO login_logs (ip, username, action, success, user_agent) VALUES (?, ?, ?, 1, ?)',
                [clientIP, username, 'logout', userAgent]
            );
        }

        req.session.destroy();
        res.redirect('/hradmin/login');
    });

    // Dashboard
    app.get('/hradmin', requireAuth, async (req, res) => {
        try {
            const linkCount = await dbGet('SELECT COUNT(*) as count FROM links');
            const totalClicks = await dbGet('SELECT COALESCE(SUM(clicks), 0) as total FROM links');
            const topLinks = await dbAll('SELECT * FROM links ORDER BY clicks DESC LIMIT 5');

            res.render('dashboard', {
                page: 'overview',
                domain: DOMAIN,
                stats: {
                    linkCount: linkCount.count,
                    totalClicks: totalClicks.total,
                    topLinks
                },
                success: res.locals.success,
                error: res.locals.error
            });
        } catch (err) {
            res.render('dashboard', { page: 'overview', domain: DOMAIN, stats: { linkCount: 0, totalClicks: 0, topLinks: [] }, success: null, error: 'Veri yüklenemedi' });
        }
    });

    // Linkler sayfası
    app.get('/hradmin/links', requireAuth, async (req, res) => {
        try {
            const links = await dbAll('SELECT * FROM links ORDER BY created_at DESC');
            res.render('dashboard', {
                page: 'links',
                domain: DOMAIN,
                links,
                success: res.locals.success,
                error: res.locals.error
            });
        } catch (err) {
            res.render('dashboard', { page: 'links', domain: DOMAIN, links: [], success: null, error: 'Linkler yüklenemedi' });
        }
    });

    // Kullanıcılar sayfası
    app.get('/hradmin/users', requireAuth, requireAdmin, async (req, res) => {
        try {
            const users = await dbAll('SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at DESC');
            res.render('dashboard', {
                page: 'users',
                domain: DOMAIN,
                users,
                currentUserId: req.session.userId,
                success: res.locals.success,
                error: res.locals.error
            });
        } catch (err) {
            res.render('dashboard', { page: 'users', domain: DOMAIN, users: [], currentUserId: null, success: null, error: 'Kullanıcılar yüklenemedi' });
        }
    });

    // Loglar sayfası
    app.get('/hradmin/logs', requireAuth, requireAdmin, async (req, res) => {
        try {
            // Query parametreleri
            const logType = req.query.type || 'all';
            const limit = parseInt(req.query.limit) || 100;
            const search = req.query.search || '';

            // Click logları
            let clickLogs = [];
            if (logType === 'all' || logType === 'click') {
                let clickQuery = 'SELECT *, "click" as log_type FROM click_logs';
                const clickParams = [];

                if (search) {
                    clickQuery += ' WHERE ip LIKE ? OR slug LIKE ? OR browser LIKE ?';
                    clickParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
                }

                clickQuery += ' ORDER BY created_at DESC LIMIT ?';
                clickParams.push(limit);

                clickLogs = await dbAll(clickQuery, clickParams);
            }

            // Login/Logout logları
            let loginLogs = [];
            if (logType === 'all' || logType === 'auth') {
                let loginQuery = 'SELECT *, "auth" as log_type FROM login_logs';
                const loginParams = [];

                if (search) {
                    loginQuery += ' WHERE ip LIKE ? OR username LIKE ?';
                    loginParams.push(`%${search}%`, `%${search}%`);
                }

                loginQuery += ' ORDER BY created_at DESC LIMIT ?';
                loginParams.push(limit);

                loginLogs = await dbAll(loginQuery, loginParams);
            }

            // Aktivite logları
            let activityLogs = [];
            if (logType === 'all' || logType === 'activity') {
                let activityQuery = 'SELECT *, "activity" as log_type FROM activity_logs';
                const activityParams = [];

                if (search) {
                    activityQuery += ' WHERE ip LIKE ? OR username LIKE ? OR target_name LIKE ? OR action LIKE ?';
                    activityParams.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
                }

                activityQuery += ' ORDER BY created_at DESC LIMIT ?';
                activityParams.push(limit);

                activityLogs = await dbAll(activityQuery, activityParams);
            }

            // Tüm logları birleştir ve sırala
            let allLogs = [...clickLogs, ...loginLogs, ...activityLogs];
            allLogs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            allLogs = allLogs.slice(0, limit);

            // İstatistikler
            const stats = {
                totalClicks: (await dbGet('SELECT COUNT(*) as count FROM click_logs')).count,
                totalLogins: (await dbGet('SELECT COUNT(*) as count FROM login_logs')).count,
                successfulLogins: (await dbGet('SELECT COUNT(*) as count FROM login_logs WHERE success = 1 AND action = "login"')).count,
                failedLogins: (await dbGet('SELECT COUNT(*) as count FROM login_logs WHERE success = 0')).count,
                totalActivities: (await dbGet('SELECT COUNT(*) as count FROM activity_logs')).count,
                todayClicks: (await dbGet("SELECT COUNT(*) as count FROM click_logs WHERE date(created_at) = date('now')")),
                uniqueIPs: (await dbGet('SELECT COUNT(DISTINCT ip) as count FROM click_logs')).count
            };
            stats.todayClicks = stats.todayClicks ? stats.todayClicks.count : 0;

            res.render('dashboard', {
                page: 'logs',
                domain: DOMAIN,
                logs: allLogs,
                stats,
                filters: { type: logType, limit, search },
                success: res.locals.success,
                error: res.locals.error
            });
        } catch (err) {
            console.error('Logs error:', err);
            res.render('dashboard', {
                page: 'logs',
                domain: DOMAIN,
                logs: [],
                stats: { totalClicks: 0, totalLogins: 0, successfulLogins: 0, failedLogins: 0, totalActivities: 0, todayClicks: 0, uniqueIPs: 0 },
                filters: { type: 'all', limit: 100, search: '' },
                success: null,
                error: 'Loglar yüklenemedi'
            });
        }
    });

    // Link logları API
    app.get('/hradmin/api/logs/:linkId', requireAuth, async (req, res) => {
        const linkId = parseInt(req.params.linkId);

        if (isNaN(linkId)) {
            return res.status(400).json({ error: 'Geçersiz link ID' });
        }

        try {
            const logs = await dbAll(
                'SELECT * FROM click_logs WHERE link_id = ? ORDER BY created_at DESC LIMIT 50',
                [linkId]
            );
            res.json(logs);
        } catch (err) {
            console.error('Log fetch error:', err);
            res.status(500).json({ error: 'Loglar yüklenemedi' });
        }
    });

    // Yeni link ekleme
    app.post('/hradmin/links', requireAuth, requireAdmin, async (req, res) => {
        const { slug, targetUrl, title } = req.body;

        if (!slug || !targetUrl) {
            req.session.error = 'Slug ve hedef URL gerekli';
            return res.redirect('/hradmin/links');
        }

        // URL doğrulama
        if (!isValidUrl(targetUrl) || !isSafeUrl(targetUrl)) {
            req.session.error = 'Geçersiz veya güvensiz URL';
            return res.redirect('/hradmin/links');
        }

        const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-_]/g, '');

        if (cleanSlug.length < 1) {
            req.session.error = 'Geçersiz slug';
            return res.redirect('/hradmin/links');
        }

        const reserved = ['hradmin', 'api', 'admin', 'static', 'public', 'login', 'logout'];
        if (reserved.includes(cleanSlug)) {
            req.session.error = 'Bu isim rezerve edilmiş';
            return res.redirect('/hradmin/links');
        }

        try {
            const existing = await dbGet('SELECT * FROM links WHERE slug = ?', [cleanSlug]);
            if (existing) {
                req.session.error = 'Bu kısa isim zaten kullanılıyor';
                return res.redirect('/hradmin/links');
            }

            const result = await dbRun('INSERT INTO links (slug, target_url, title) VALUES (?, ?, ?)', [cleanSlug, targetUrl, title || '']);
            await logActivity(req, 'create', 'link', 'link', result.lastID, cleanSlug, `Hedef: ${targetUrl}`);
            req.session.success = 'Link oluşturuldu';
        } catch (err) {
            req.session.error = 'Link oluşturulamadı';
        }

        res.redirect('/hradmin/links');
    });

    // Link düzenleme sayfası
    app.get('/hradmin/links/:id/edit', requireAuth, async (req, res) => {
        try {
            const id = parseInt(req.params.id);
            if (isNaN(id)) {
                req.session.error = 'Geçersiz link ID';
                return res.redirect('/hradmin/links');
            }

            const link = await dbGet('SELECT * FROM links WHERE id = ?', [id]);
            if (!link) {
                req.session.error = 'Link bulunamadı';
                return res.redirect('/hradmin/links');
            }
            res.render('edit-link', { link });
        } catch (err) {
            req.session.error = 'Link yüklenemedi';
            res.redirect('/hradmin/links');
        }
    });

    // Link güncelleme
    app.post('/hradmin/links/:id/edit', requireAuth, requireAdmin, async (req, res) => {
        const { slug, targetUrl, title } = req.body;
        const id = parseInt(req.params.id);

        if (isNaN(id)) {
            req.session.error = 'Geçersiz link ID';
            return res.redirect('/hradmin/links');
        }

        // URL doğrulama
        if (!isValidUrl(targetUrl) || !isSafeUrl(targetUrl)) {
            req.session.error = 'Geçersiz veya güvensiz URL';
            return res.redirect(`/hradmin/links/${id}/edit`);
        }

        try {
            const link = await dbGet('SELECT * FROM links WHERE id = ?', [id]);
            if (!link) {
                req.session.error = 'Link bulunamadı';
                return res.redirect('/hradmin/links');
            }

            const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-_]/g, '');
            const reserved = ['hradmin', 'api', 'admin', 'static', 'public', 'login', 'logout'];

            if (reserved.includes(cleanSlug)) {
                req.session.error = 'Bu isim rezerve edilmiş';
                return res.redirect(`/hradmin/links/${id}/edit`);
            }

            const existing = await dbGet('SELECT * FROM links WHERE slug = ? AND id != ?', [cleanSlug, id]);
            if (existing) {
                req.session.error = 'Bu kısa isim zaten kullanılıyor';
                return res.redirect(`/hradmin/links/${id}/edit`);
            }

            await dbRun('UPDATE links SET slug = ?, target_url = ?, title = ? WHERE id = ?', [cleanSlug, targetUrl, title || '', id]);
            await logActivity(req, 'update', 'link', 'link', id, cleanSlug, `Eski: ${link.slug} -> Yeni: ${cleanSlug}`);
            req.session.success = 'Link güncellendi';
        } catch (err) {
            req.session.error = 'Link güncellenemedi';
        }

        res.redirect('/hradmin/links');
    });

    // Link silme
    app.post('/hradmin/links/:id/delete', requireAuth, requireAdmin, async (req, res) => {
        const id = parseInt(req.params.id);

        if (isNaN(id)) {
            req.session.error = 'Geçersiz link ID';
            return res.redirect('/hradmin/links');
        }

        try {
            const link = await dbGet('SELECT * FROM links WHERE id = ?', [id]);
            if (!link) {
                req.session.error = 'Link bulunamadı';
                return res.redirect('/hradmin/links');
            }

            await dbRun('DELETE FROM links WHERE id = ?', [id]);
            await logActivity(req, 'delete', 'link', 'link', id, link.slug, `Silinen hedef: ${link.target_url}`);
            req.session.success = 'Link silindi';
        } catch (err) {
            req.session.error = 'Link silinemedi';
        }

        res.redirect('/hradmin/links');
    });

    // Ayarlar sayfası
    app.get('/hradmin/settings', requireAuth, requireAdmin, async (req, res) => {
        const defaultRedirect = await getSetting('defaultRedirect');
        const users = await dbAll('SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at DESC');
        res.render('dashboard', {
            page: 'settings',
            domain: DOMAIN,
            settings: { defaultRedirect },
            users,
            currentUserId: req.session.userId,
            success: res.locals.success,
            error: res.locals.error
        });
    });

    // Ayarları güncelle (sadece genel ayarlar)
    app.post('/hradmin/settings', requireAuth, async (req, res) => {
        const { defaultRedirect } = req.body;

        try {
            if (defaultRedirect) {
                if (!isValidUrl(defaultRedirect) || !isSafeUrl(defaultRedirect)) {
                    req.session.error = 'Geçersiz yönlendirme URL\'si';
                    return res.redirect('/hradmin/settings');
                }
                await setSetting('defaultRedirect', defaultRedirect);
                await logActivity(req, 'update', 'settings', 'settings', null, 'defaultRedirect', `Yeni değer: ${defaultRedirect}`);
            }

            req.session.success = 'Ayarlar güncellendi';
        } catch (err) {
            req.session.error = 'Ayarlar güncellenemedi';
        }

        res.redirect('/hradmin/settings');
    });

    // Yeni kullanıcı oluştur
    app.post('/hradmin/users/create', requireAuth, async (req, res) => {
        const { username, password, role } = req.body;

        if (!username || !password) {
            req.session.error = 'Kullanıcı adı ve şifre gerekli';
            return res.redirect('/hradmin/settings');
        }

        if (password.length < 8) {
            req.session.error = 'Şifre en az 8 karakter olmalı';
            return res.redirect('/hradmin/settings');
        }

        const cleanUsername = username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
        if (cleanUsername.length < 3) {
            req.session.error = 'Kullanıcı adı en az 3 karakter olmalı';
            return res.redirect('/hradmin/settings');
        }

        try {
            const existing = await dbGet('SELECT id FROM users WHERE username = ?', [cleanUsername]);
            if (existing) {
                req.session.error = 'Bu kullanıcı adı zaten alınmış';
                return res.redirect('/hradmin/settings');
            }

            const hashedPassword = await hashPassword(password);
            const result = await dbRun('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                [cleanUsername, hashedPassword, role || 'user']);
            await logActivity(req, 'create', 'user', 'user', result.lastID, cleanUsername, `Rol: ${role || 'user'}`);

            req.session.success = `Kullanıcı "${cleanUsername}" oluşturuldu`;
        } catch (err) {
            console.error('User create error:', err);
            req.session.error = 'Kullanıcı oluşturulamadı';
        }

        res.redirect('/hradmin/settings');
    });

    // Kullanıcı sil
    app.post('/hradmin/users/:id/delete', requireAuth, async (req, res) => {
        const userId = parseInt(req.params.id);

        if (isNaN(userId)) {
            req.session.error = 'Geçersiz kullanıcı ID';
            return res.redirect('/hradmin/settings');
        }

        // Kendini silmeye çalışıyor mu?
        if (userId === req.session.userId) {
            req.session.error = 'Kendinizi silemezsiniz';
            return res.redirect('/hradmin/settings');
        }

        try {
            const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
            if (!user) {
                req.session.error = 'Kullanıcı bulunamadı';
                return res.redirect('/hradmin/settings');
            }

            // Tek admin mi kontrol et
            const adminCount = await dbGet('SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
            if (user.role === 'admin' && adminCount.count <= 1) {
                req.session.error = 'Son admin kullanıcısını silemezsiniz';
                return res.redirect('/hradmin/settings');
            }

            await dbRun('DELETE FROM users WHERE id = ?', [userId]);
            await logActivity(req, 'delete', 'user', 'user', userId, user.username, `Rol: ${user.role}`);
            req.session.success = `Kullanıcı "${user.username}" silindi`;
        } catch (err) {
            console.error('User delete error:', err);
            req.session.error = 'Kullanıcı silinemedi';
        }

        res.redirect('/hradmin/settings');
    });

    // Kullanıcı şifre değiştir
    app.post('/hradmin/users/:id/password', requireAuth, async (req, res) => {
        const userId = parseInt(req.params.id);
        const { newPassword } = req.body;

        if (isNaN(userId)) {
            req.session.error = 'Geçersiz kullanıcı ID';
            return res.redirect('/hradmin/settings');
        }

        if (!newPassword || newPassword.length < 8) {
            req.session.error = 'Şifre en az 8 karakter olmalı';
            return res.redirect('/hradmin/settings');
        }

        try {
            const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
            if (!user) {
                req.session.error = 'Kullanıcı bulunamadı';
                return res.redirect('/hradmin/settings');
            }

            const hashedPassword = await hashPassword(newPassword);
            await dbRun('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
            await logActivity(req, 'update', 'user', 'user', userId, user.username, 'Şifre değiştirildi');
            req.session.success = `"${user.username}" kullanıcısının şifresi değiştirildi`;
        } catch (err) {
            console.error('Password change error:', err);
            req.session.error = 'Şifre değiştirilemedi';
        }

        res.redirect('/hradmin/settings');
    });

    // ============================================
    // LINK YÖNLENDİRME
    // ============================================
    app.get('/:slug', async (req, res) => {
        const { slug } = req.params;
        const clientIP = getClientIP(req);

        // Slug sanitization
        const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-_]/g, '');

        try {
            const link = await dbGet('SELECT * FROM links WHERE slug = ?', [cleanSlug]);

            if (link) {
                // Detaylı bilgileri topla
                const userAgent = req.headers['user-agent'] || '';
                const referer = req.headers['referer'] || req.headers['referrer'] || 'direct';
                const language = req.headers['accept-language']?.split(',')[0] || 'unknown';

                // User-Agent parse
                const deviceInfo = parseUserAgent(userAgent);

                // Click log kaydet
                await dbRun(`
                    INSERT INTO click_logs 
                    (link_id, slug, target_url, ip, referer, user_agent, browser, browser_version, os, os_version, device_type, language)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [
                    link.id,
                    cleanSlug,
                    link.target_url,
                    clientIP,
                    referer,
                    userAgent,
                    deviceInfo.browser,
                    deviceInfo.browserVersion,
                    deviceInfo.os,
                    deviceInfo.osVersion,
                    deviceInfo.deviceType,
                    language
                ]);

                // Click sayısını artır
                await dbRun('UPDATE links SET clicks = clicks + 1, last_clicked_at = CURRENT_TIMESTAMP WHERE id = ?', [link.id]);

                console.log(`🔗 Link tıklandı: /${cleanSlug} -> ${link.target_url} | IP: ${clientIP} | ${deviceInfo.browser}/${deviceInfo.os}`);

                return res.redirect(301, link.target_url);
            }
        } catch (err) {
            console.error('Redirect error:', err);
        }

        const defaultRedirect = await getSetting('defaultRedirect');
        res.redirect(301, defaultRedirect || process.env.DOMAIN);
    });

    // ============================================
    // 404 Handler
    // ============================================
    app.use((req, res) => {
        res.status(404).json({ error: 'Sayfa bulunamadı' });
    });

    // ============================================
    // SUNUCUYU BAŞLAT
    // ============================================
    app.listen(PORT, () => {
        console.log(`🚀 Hunterrock GO çalışıyor: ${process.env.DOMAIN}`);
        console.log(`📊 Admin Panel: ${process.env.DOMAIN}/hradmin`);
        console.log(`💾 Veritabanı: SQLite (hrgo.db)`);
        console.log(`🔒 Güvenlik: Helmet + Rate Limit + Bcrypt + Session Token`);
    });
})();

process.on('SIGINT', () => {
    db.close();
    process.exit();
});
