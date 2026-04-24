const fs = require('fs');
const envPath = require('path').join(__dirname, '.env');

if (!fs.existsSync(envPath)) {
    console.log('');
    console.log('⚠️  .env dosyası bulunamadı!');
    console.log('   Kurulum sihirbazını başlatmak için:');
    console.log('');
    console.log('   npm run setup');
    console.log('');
    process.exit(1);
}

require('dotenv').config();

const requiredEnvs = ['SESSION_SECRET', 'DOMAIN', 'PORT'];
const missingEnvs = requiredEnvs.filter(env => !process.env[env]);

if (missingEnvs.length > 0) {
    console.error(`\n❌ KRİTİK HATA: Eksik çevre değişkenleri bulundu: ${missingEnvs.join(', ')}`);
    console.error('Lütfen .env dosyanızı kontrol edin veya "npm run setup" komutunu çalıştırın.\n');
    process.exit(1);
}

const serverSecret = process.env.SESSION_SECRET;

const express = require('express');

const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const xss = require('xss');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const https = require('https');
const http = require('http');
const geoRequestQueue = [];
const pendingGeoRequests = new Map();
let isProcessingGeoQueue = false;

async function processGeoQueue() {
    if (isProcessingGeoQueue || geoRequestQueue.length === 0) return;
    isProcessingGeoQueue = true;

    while (geoRequestQueue.length > 0) {
        const { ip, resolve } = geoRequestQueue.shift();

        try {
            https.get(`https://ipwho.is/${encodeURIComponent(ip)}`, (res) => {
                let body = "";
                res.on("data", (chunk) => body += chunk);
                res.on("end", async () => {
                    try {
                        const data = JSON.parse(body);
                        if (data && data.success === true) {
                            const geo = {
                                country: data.country || null,
                                country_code: data.country_code || null,
                                city: data.city || null,
                                region: data.region || null,
                                timezone: data.timezone?.id || null,
                                ll: (data.latitude && data.longitude) ? `${data.latitude},${data.longitude}` : null
                            };

                            console.log(`✅ GeoIP Başarılı [${ip}]: ${geo.city}, ${geo.country}`);

                            await dbRun(`
                                INSERT INTO ip_cache (ip, country, country_code, city, region, timezone, ll, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                                ON CONFLICT(ip) DO UPDATE SET
                                country=excluded.country, country_code=excluded.country_code, 
                                city=excluded.city, region=excluded.region,
                                timezone=excluded.timezone, ll=excluded.ll, updated_at=CURRENT_TIMESTAMP
                            `, [ip, geo.country, geo.country_code, geo.city, geo.region, geo.timezone, geo.ll]);

                            await dbRun(`
                                UPDATE click_logs 
                                SET country = ?, country_code = ?, city = ?, region = ?, timezone = ?, ll = ?
                                WHERE ip = ? AND (country IS NULL OR country = '' OR country = 'Bilinmiyor')
                            `, [geo.country, geo.country_code, geo.city, geo.region, geo.timezone, geo.ll, ip]);

                            resolve(geo);
                        } else {
                            console.warn(`⚠️ GeoIP API Hatası [${ip}]:`, data?.message || 'Bilinmeyen hata');
                            resolve({});
                        }
                    } catch (e) {
                        resolve({});
                    }
                });
            }).on("error", (err) => {
                console.error(`❌ GeoIP HTTPS Hatası [${ip}]:`, err.message);
                resolve({});
            });
        } catch (err) {
            console.error(`❌ GeoIP Kuyruk Hatası [${ip}]:`, err.message);
            resolve({});
        }

        await new Promise(r => setTimeout(r, 1400));
    }

    isProcessingGeoQueue = false;
}

async function getGeoInfo(ip) {
    if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.')) return {};

    try {
        const cached = await dbGet(`
            SELECT *, (strftime('%s', 'now') - strftime('%s', updated_at)) as age 
            FROM ip_cache WHERE ip = ?`, [ip]);

        if (cached && cached.age < (7 * 24 * 60 * 60)) {
            return {
                country: cached.country,
                country_code: cached.country_code,
                city: cached.city,
                region: cached.region,
                timezone: cached.timezone,
                ll: cached.ll
            };
        }

        if (pendingGeoRequests.has(ip)) {
            return pendingGeoRequests.get(ip);
        }

        const geoPromise = new Promise((resolve) => {
            geoRequestQueue.push({
                ip, resolve: (val) => {
                    pendingGeoRequests.delete(ip);
                    resolve(val);
                }
            });
        });

        pendingGeoRequests.set(ip, geoPromise);
        processGeoQueue();

        return geoPromise;
    } catch (err) {
        return {};
    }
}
const jwt = require('jsonwebtoken');
const { version: APP_VERSION } = require('./package.json');


const app = express();
const PORT = process.env.PORT;
const DOMAIN = process.env.DOMAIN;

app.locals.version = APP_VERSION;
app.locals.favicon = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'><path fill='%234facfe' d='M326.612 185.391c59.747 59.809 58.927 155.698.36 214.59l-61.172 61.403c-58.566 58.892-155.416 58.984-214.303.386l-3.991-3.927c-9.424-9.275-9.589-24.476-.392-33.908l14.908-15.247c9.193-9.399 24.144-9.552 33.528-.357l3.991 3.927c34.172 33.657 89.215 33.602 123.386-.386l61.172-61.403c34.172-34.029 34.079-89.226-.304-123.56l-3.991-3.927c-9.385-9.215-9.511-24.316-.312-33.657l15.145-15.35c9.193-9.313 24.116-9.424 33.528-.157l3.978 3.91zM185.391 326.612c-59.747-59.809-58.927-155.698-.36-214.59l61.172-61.403c58.566-58.892 155.416-58.984 214.303-.386l3.991 3.927c9.424 9.275 9.589 24.476.392 33.908l-14.908 15.247c-9.193 9.399-24.144 9.552-33.528.357l-3.991-3.927c-34.172-33.657-89.215-33.602-123.386.386l-61.172 61.403c-34.172 34.029-34.079 89.226.304 123.56l3.991 3.927c34.304 33.657 33.657 89.215 0 123.386l-15.145 15.35c-9.193 9.313-24.116 9.424-33.528.157l-3.978-3.91z'/></svg>";

app.set('trust proxy', [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '127.0.0.1', '::1'
]);


app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com", "https://static.cloudflareinsights.com", "*.cloudflare.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            styleSrcAttr: ["'unsafe-inline'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            mediaSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https://cloudflareinsights.com", "https://static.cloudflareinsights.com", "*.cloudflareinsights.com"]
        }
    }
}));


const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    message: 'Çok fazla istek gönderdiniz, lütfen daha sonra tekrar deneyin.',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path.startsWith('/hradmin'),
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Çok fazla başarısız giriş denemesi. 15 dakika sonra tekrar deneyin.',
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
});

app.use(generalLimiter);

// ============================================
// GÜVENLİK - Başarısız Giriş Loglama
// ============================================
function logFailedLogin(ip, username) {
    console.log(`⚠️  Başarısız giriş denemesi: IP=${ip}, Kullanıcı=${username}`);
}

function logSuccessfulLogin(ip, username) {
    console.log(`✅ Başarılı giriş: IP=${ip}, Kullanıcı=${username}`);
}

function getClientIP(req) {
    if (req.headers['cf-connecting-ip']) {
        return req.headers['cf-connecting-ip'];
    }
    return req.headers['x-forwarded-for']?.split(',')[0] ||
        req.headers['x-real-ip'] ||
        req.ip ||
        req.connection?.remoteAddress ||
        'unknown';
}

app.locals.getFlagEmoji = function (countryCode) {
    if (!countryCode || countryCode === '??') return '🏳️';
    try {
        const codePoints = countryCode
            .toUpperCase()
            .split('')
            .map(char => 127397 + char.charCodeAt());
        return String.fromCodePoint(...codePoints);
    } catch (e) {
        return '🏳️';
    }
};

const db = new sqlite3.Database(path.join(__dirname, 'hrgo.db'), (err) => {
    if (err) {
        console.error('🚨 Veritabanı bağlantı hatası:', err.message);
        process.exit(1);
    }
});

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
            country_code TEXT,
            city TEXT,
            region TEXT,
            timezone TEXT,
            ll TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (link_id) REFERENCES links(id)
        )
    `);

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
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            country_code TEXT,
            city TEXT,
            region TEXT,
            timezone TEXT,
            ll TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    const addColumn = (table, col, type) => {
        db.run(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`, (err) => {
            if (err && !err.message.includes('duplicate column name')) {
                console.error(`❌ Hata: ${table}.${col} eklenemedi:`, err.message);
            }
        });
    };

    addColumn('click_logs', 'country_code', 'TEXT');
    addColumn('click_logs', 'city', 'TEXT');
    addColumn('click_logs', 'region', 'TEXT');
    addColumn('click_logs', 'timezone', 'TEXT');
    addColumn('click_logs', 'll', 'TEXT');
    addColumn('ip_cache', 'country_code', 'TEXT');
    addColumn('activity_logs', 'user_agent', 'TEXT');


    db.run('CREATE INDEX IF NOT EXISTS idx_links_slug ON links(slug)');
    db.run('CREATE INDEX IF NOT EXISTS idx_click_logs_link_id ON click_logs(link_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_click_logs_created ON click_logs(created_at)');
    db.run('CREATE INDEX IF NOT EXISTS idx_click_logs_ip ON click_logs(ip)');
    db.run('CREATE INDEX IF NOT EXISTS idx_login_logs_created ON login_logs(created_at)');
    db.run('CREATE INDEX IF NOT EXISTS idx_login_logs_ip ON login_logs(ip)');
    db.run('CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at)');

    db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('domain', ?)`, [DOMAIN]);

    db.serialize(async () => {
        db.get("SELECT value FROM settings WHERE key = 'domain'", (err, row) => {
            const dbDomain = row ? row.value : null;
            const envDomain = process.env.DOMAIN;

            if (!dbDomain || dbDomain !== envDomain) {
                console.log('\n❌ KRİTİK ALAN ADI UYUMSUZLUĞU!');
                console.log(`   .env: ${envDomain}`);
                console.log(`   DB:   ${dbDomain || 'Bulunamadı'}`);
                console.log('💡 Lütfen kurulum sihirbazını çalıştırın veya DB/ENV değerlerini eşitleyin.\n');
                global.domainError = { env: envDomain, db: dbDomain };
            }
        });

        db.get("SELECT COUNT(*) as count FROM users WHERE role = 'admin'", (err, row) => {
            if (err || !row || row.count === 0) {
                console.log('\n❌ HATA: Sistemde hiç admin kullanıcısı bulunamadı!');
                console.log('💡 Kurulumu tamamlamak için: npm run setup\n');
            }
        });
    });
});

app.use((req, res, next) => {
    res.locals.getFlagEmoji = (countryCode) => {
        if (!countryCode || countryCode === 'Unknown') return '🏳️';
        try {
            const codePoints = countryCode
                .toUpperCase()
                .split('')
                .map(char => 127397 + char.charCodeAt());
            return String.fromCodePoint(...codePoints);
        } catch (e) { return '🏳️'; }
    };

    const configuredDomain = process.env.DOMAIN;
    if (!configuredDomain) return next();

    if (global.domainError && !req.path.startsWith('/public')) {
        return res.status(403).send(`
            <body style="background: #0b0c10; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
                <div style="text-align: center; padding: 3rem; border: 1px solid #1f2833; border-radius: 16px; background: rgba(31, 40, 51, 0.3); max-width: 500px; backdrop-filter: blur(10px);">
                    <h1 style="color: #f59e0b; margin-top: 0; font-size: 2rem;">⚠️ Veritabanı Uyumsuzluğu</h1>
                    <p style="color: #94a3b8; line-height: 1.6; margin-bottom: 2rem;">Veritabanındaki alan adı ile sunucu yapılandırması (.env) birbiriyle uyuşmuyor. Güvenlik nedeniyle sistem kilitlendi.</p>
                    <div style="background: rgba(11, 12, 16, 0.6); padding: 20px; border-radius: 12px; text-align: left; font-family: monospace; font-size: 14px; border: 1px solid #1f2833;">
                        <div style="color: #4facfe; margin-bottom: 8px;">📁 .env: ${global.domainError.env}</div>
                        <div style="color: #ef4444;">🗄️ DB:   ${global.domainError.db || 'Eksik'}</div>
                    </div>
                    <p style="font-size: 0.85rem; color: #64748b; margin-top: 2rem;">Lütfen veritabanındaki <b>settings</b> tablosunu veya .env dosyasını güncelleyerek değerleri eşitleyin.</p>
                </div>
            </body>
        `);
    }

    const cleanConfigured = configuredDomain.replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
    const currentHost = req.get('host').toLowerCase().split(':')[0];

    if (currentHost !== cleanConfigured && !req.path.startsWith('/public') && !req.path.startsWith('/hradmin/setup')) {
        return res.status(403).send(`
            <body style="background: #0b0c10; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
                <div style="text-align: center; padding: 3rem; border: 1px solid #1f2833; border-radius: 16px; background: rgba(31, 40, 51, 0.3); max-width: 500px; backdrop-filter: blur(10px);">
                    <h1 style="color: #ef4444; margin-top: 0; font-size: 2rem;">🛑 Alan Adı Uyumsuzluğu</h1>
                    <p style="color: #94a3b8; line-height: 1.6; margin-bottom: 2rem;">Bu uygulama sadece yetkili alan adı üzerinden çalışabilir. Mevcut yapılandırma ile erişim sağladığınız adres eşleşmiyor.</p>
                    <div style="background: rgba(11, 12, 16, 0.6); padding: 20px; border-radius: 12px; text-align: left; font-family: monospace; font-size: 14px; border: 1px solid #1f2833;">
                        <div style="color: #4facfe; margin-bottom: 8px;">✔ Beklenen: ${cleanConfigured}</div>
                        <div style="color: #ef4444;">✖ Mevcut: ${currentHost}</div>
                    </div>
                    <p style="font-size: 0.85rem; color: #64748b; margin-top: 2rem;">Eğer sunucu değişikliği yaptıysanız lütfen .env dosyanızı güncelleyin.</p>
                </div>
            </body>
        `);
    }
    next();
});

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

async function logActivity(req, action, category, targetType = null, targetId = null, targetName = null, details = null) {
    try {
        const userId = req.user ? req.user.userId : null || null;
        const username = req.user ? req.user.username : 'Sistem' || 'Sistem';
        const ip = getClientIP(req);
        const userAgent = req.headers['user-agent'] || '';

        await dbRun(
            `INSERT INTO activity_logs (user_id, username, action, category, target_type, target_id, target_name, details, ip, user_agent) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [userId, username, action, category, targetType, targetId, targetName, details, ip, userAgent]
        );

        getGeoInfo(ip).catch(() => { });
    } catch (err) {
        console.error('Activity log error:', err);
    }
}

async function hashPassword(password) {
    return bcrypt.hash(password, 12);
}

function parseUserAgent(ua) {
    const result = {
        browser: 'Unknown',
        browserVersion: '',
        os: 'Unknown',
        osVersion: '',
        deviceType: 'Desktop'
    };

    if (!ua) return result;

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

    if (ua.includes('Mobile') || ua.includes('Android') && !ua.includes('Tablet')) {
        result.deviceType = 'Mobile';
    } else if (ua.includes('iPad') || ua.includes('Tablet')) {
        result.deviceType = 'Tablet';
    } else if (ua.includes('Bot') || ua.includes('bot') || ua.includes('Crawler') || ua.includes('Spider')) {
        result.deviceType = 'Bot';
    }

    return result;
}

function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

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
app.use(cookieParser(serverSecret));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// GÜVENLİK - Global XSS Temizleme (Sanitization)
// ============================================
function sanitizeObject(obj) {
    if (typeof obj === 'string') {
        return xss(obj);
    }
    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item));
    }
    if (typeof obj === 'object' && obj !== null) {
        const sanitized = {};
        for (const key in obj) {
            sanitized[key] = sanitizeObject(obj[key]);
        }
        return sanitized;
    }
    return obj;
}

app.use((req, res, next) => {
    if (req.body) req.body = sanitizeObject(req.body);
    if (req.query) req.query = sanitizeObject(req.query);
    if (req.params) req.params = sanitizeObject(req.params);
    next();
});

const generateCsrfToken = () => crypto.randomBytes(32).toString('hex');

app.use((req, res, next) => {
    if (!req.cookies.csrf_token) {
        res.cookie('csrf_token', generateCsrfToken(), { httpOnly: true, path: '/' });
    }

    res.locals.csrfToken = req.cookies.csrf_token || '';

    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }

    if (req.url === '/hradmin/login') {
        return next();
    }

    const submittedToken = req.body._csrf || req.headers['x-csrf-token'];

    if (!submittedToken || submittedToken !== req.cookies.csrf_token) {
        console.warn(`🚫 CSRF Engellendi: IP=${getClientIP(req)}, URL=${req.url}`);
        return res.status(403).json({ error: 'Güvenlik doğrulaması başarısız (CSRF)' });
    }

    next();
});

async function requireAuth(req, res, next) {
    const token = req.cookies.auth_token;

    if (!token) {
        return res.redirect('/hradmin/login');
    }

    try {
        const decoded = jwt.verify(token, serverSecret);

        const user = await dbGet('SELECT * FROM users WHERE id = ?', [decoded.userId]);

        if (!user) {
            console.warn(`⚠️ JWT Geçersiz: Kullanıcı silinmiş veya bulunamadı (ID: ${decoded.userId})`);
            res.clearCookie('auth_token');
            return res.redirect('/hradmin/login');
        }

        res.locals.userId = user.id;
        res.locals.username = user.username;
        res.locals.userRole = user.role;

        req.user = {
            userId: user.id,
            username: user.username,
            userRole: user.role
        };

        return next();
    } catch (err) {
        console.warn('⚠️ JWT Geçersiz:', err.message);
        res.clearCookie('auth_token');
        return res.redirect('/hradmin/login');
    }
}

function requireAdmin(req, res, next) {
    if (req.user && req.user.userRole === 'admin') {
        return next();
    }
    res.cookie('flash_error', 'Bu sayfaya erişim yetkiniz yok', { httpOnly: true, path: '/' });
    res.redirect('/hradmin');
}

app.use((req, res, next) => {
    res.locals.success = req.cookies.flash_success || null;
    res.locals.error = req.cookies.flash_error || null;
    res.clearCookie('flash_success');
    res.clearCookie('flash_error');

    if (req.user) {
        res.locals.username = req.user.username;
        res.locals.userRole = req.user.userRole;
        res.locals.userId = req.user.userId;
    } else {
        res.locals.username = '';
        res.locals.userRole = 'user';
    }

    next();
});


function requireAjax(req, res, next) {
    const acceptHeader = req.headers['accept'] || '';
    const xRequestedWith = req.headers['x-requested-with'] || '';
    const isAjax = req.xhr || xRequestedWith === 'XMLHttpRequest' || acceptHeader.includes('application/json');

    const referer = req.headers.referer || '';
    const origin = req.headers.origin || '';

    const domainClean = DOMAIN.replace(/^https?:\/\//, '').replace(/^www\./, '');
    const isOwnDomain = referer.includes(domainClean) || origin.includes(domainClean) ||
        referer.includes('localhost') || referer.includes('127.0.0.1');

    if (isAjax && (isOwnDomain || !referer)) {
        return next();
    }

    console.log(`🚫 API Erişimi Engellendi: Ajax=${isAjax}, Referer=${referer}, Origin=${origin}`);
    return res.status(403).json({ error: 'Erişim engellendi' });
}

app.get('/favicon.ico', (req, res) => {
    const svgCode = app.locals.favicon.split(',')[1];
    const buffer = Buffer.from(decodeURIComponent(svgCode));
    res.type('image/svg+xml').send(buffer);
});

app.get('/', (req, res) => {
    res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Hunterrock GO - Status</title>
                <link rel="icon" href="${app.locals.favicon}">
            <body style="background: #0b0c10; color: #4facfe; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
                <div style="text-align: center; padding: 2rem; border: 1px solid #1f2833; border-radius: 12px; background: rgba(31, 40, 51, 0.2);">
                    <h1 style="margin-top: 0;">🚀 Hunterrock GO</h1>
                    <p>Sistem durumu: <span style="color: #00f2fe; font-family: monospace;">Online</span></p>
                    <p style="color: #8892b0; font-size: 0.9rem;">API ve Link Kısaltma Servisi Çalışıyor</p>
                </div>
            </body>
            </html>
        `);
});

app.get('/hradmin/login', (req, res) => {
    if (req.user) {
        return res.redirect('/hradmin');
    }

    res.clearCookie('flash_error');

    res.render('login', {
        error: req.cookies.flash_error || res.locals.error || null,
        csrfToken: req.cookies.csrf_token || '',
        favicon: app.locals.favicon
    });
});

app.post('/hradmin/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.headers['user-agent'] || '';

    try {
        const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);

        if (user) {
            const isValidPass = await bcrypt.compare(password, user.password);

            if (isValidPass) {
                const token = jwt.sign({
                    userId: user.id,
                    username: user.username,
                    userRole: user.role
                }, serverSecret, { expiresIn: '30d' });

                res.cookie('auth_token', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    maxAge: 30 * 24 * 60 * 60 * 1000,
                    sameSite: 'strict'
                });

                await dbRun('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

                logSuccessfulLogin(clientIP, username);
                await dbRun('INSERT INTO login_logs (ip, username, action, success, user_agent) VALUES (?, ?, ?, 1, ?)', [clientIP, username, 'login', userAgent]);

                getGeoInfo(clientIP).catch(e => console.error('Login GeoIP Hatası:', e.message));

                return res.redirect('/hradmin');
            }
        }

        logFailedLogin(clientIP, username || 'empty');
        await dbRun('INSERT INTO login_logs (ip, username, action, success, user_agent) VALUES (?, ?, ?, 0, ?)', [clientIP, username || 'empty', 'login', userAgent]);

        res.cookie('flash_error', 'Hatalı kullanıcı adı veya şifre', { httpOnly: true, path: '/' });
        res.redirect('/hradmin/login');
    } catch (err) {
        console.error('Login error:', err);
        res.cookie('flash_error', 'Giriş sırasında bir hata oluştu', { httpOnly: true, path: '/' });
        res.redirect('/hradmin/login');
    }
});

app.get('/hradmin/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.clearCookie('csrf_token');
    res.redirect('/hradmin/login');
});

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

app.get('/hradmin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await dbAll('SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at DESC');
        res.render('dashboard', {
            page: 'users',
            domain: DOMAIN,
            users,
            currentUserId: req.user ? req.user.userId : null,
            success: res.locals.success,
            error: res.locals.error
        });
    } catch (err) {
        res.render('dashboard', { page: 'users', domain: DOMAIN, users: [], currentUserId: null, success: null, error: 'Kullanıcılar yüklenemedi' });
    }
});

app.get('/hradmin/logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        const logType = req.query.type || 'all';
        const limit = parseInt(req.query.limit) || 15;
        const search = req.query.search || '';

        let queryParts = [];
        let params = [];

        if (logType === 'all' || logType === 'click') {
            let part = `SELECT c.id, c.created_at, 'click' as log_type, c.ip, c.user_agent, 
                        NULL as success, NULL as action, NULL as username, 
                        c.slug, c.referer, 
                        COALESCE(ic.country, c.country) as country, 
                        COALESCE(ic.country_code, c.country_code) as country_code, 
                        COALESCE(ic.city, c.city) as city, 
                        COALESCE(ic.region, c.region) as region, 
                        NULL as target_name, NULL as details, 
                        c.device_type, c.browser, c.os 
                        FROM click_logs c
                        LEFT JOIN ip_cache ic ON c.ip = ic.ip`;
            if (search) {
                part += ' WHERE c.ip LIKE ? OR c.slug LIKE ? OR c.browser LIKE ?';
                params.push(`%${search}%`, `%${search}%`, `%${search}%`);
            }
            queryParts.push(part);
        }

        if (logType === 'all' || logType === 'auth') {
            let part = `SELECT l.id, l.created_at, 'auth' as log_type, l.ip, l.user_agent, 
                        l.success, l.action, l.username, 
                        NULL as slug, NULL as referer, 
                        ic.country as country, ic.country_code as country_code, ic.city as city, ic.region as region, 
                        NULL as target_name, NULL as details, 
                        NULL as device_type, NULL as browser, NULL as os 
                        FROM login_logs l
                        LEFT JOIN ip_cache ic ON l.ip = ic.ip`;
            if (search) {
                part += ' WHERE l.ip LIKE ? OR l.username LIKE ?';
                params.push(`%${search}%`, `%${search}%`);
            }
            queryParts.push(part);
        }

        if (logType === 'all' || logType === 'activity') {
            let part = `SELECT a.id, a.created_at, 'activity' as log_type, a.ip, a.user_agent, 
                        NULL as success, a.action, a.username, 
                        NULL as slug, NULL as referer, 
                        ic.country as country, ic.country_code as country_code, ic.city as city, ic.region as region, 
                        a.target_name, a.details, 
                        NULL as device_type, NULL as browser, NULL as os 
                        FROM activity_logs a
                        LEFT JOIN ip_cache ic ON a.ip = ic.ip`;
            if (search) {
                part += ' WHERE a.ip LIKE ? OR a.username LIKE ? OR a.target_name LIKE ? OR a.action LIKE ?';
                params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
            }
            queryParts.push(part);
        }

        const pageNum = parseInt(req.query.page) || 1;

        let allLogs = [];
        let totalLogs = 0;

        if (queryParts.length > 0) {
            const countQuery = `SELECT COUNT(*) as total FROM (${queryParts.join(' UNION ALL ')})`;
            const countResult = await dbGet(countQuery, params);
            totalLogs = countResult.total;
        }

        const totalPages = Math.max(1, Math.ceil(totalLogs / limit));

        if (pageNum < 1 || (totalPages > 0 && pageNum > totalPages)) {
            const safePage = pageNum < 1 ? 1 : totalPages;
            const q = new URLSearchParams({ type: logType, search, limit, page: safePage });
            return res.redirect('/hradmin/logs?' + q.toString());
        }

        const offset = (pageNum - 1) * limit;

        if (queryParts.length > 0) {
            const finalQuery = `SELECT * FROM (${queryParts.join(' UNION ALL ')}) ORDER BY created_at DESC LIMIT ? OFFSET ?`;
            const queryParams = [...params, limit, offset];
            allLogs = await dbAll(finalQuery, queryParams);
        }

        const stats = await dbGet(`
                SELECT
                    (SELECT COUNT(*) FROM click_logs) as totalClicks,
                    (SELECT COUNT(*) FROM login_logs) as totalLogins,
                    (SELECT COUNT(*) FROM login_logs WHERE success = 1 AND action = 'login') as successfulLogins,
                    (SELECT COUNT(*) FROM login_logs WHERE success = 0) as failedLogins,
                    (SELECT COUNT(*) FROM activity_logs) as totalActivities,
                    (SELECT COUNT(*) FROM click_logs WHERE date(created_at) = date('now')) as todayClicks,
                    (SELECT COUNT(DISTINCT ip) FROM click_logs) as uniqueIPs
            `);

        res.render('dashboard', {
            page: 'logs',
            domain: DOMAIN,
            version: require('./package.json').version,
            logs: allLogs,
            stats,
            filters: { type: logType, limit, search, page: pageNum, totalPages },
            success: res.locals.success,
            error: res.locals.error
        });
    } catch (err) {
        console.error('Logs error:', err);
        res.render('dashboard', {
            page: 'logs',
            domain: DOMAIN,
            version: require('./package.json').version,
            logs: [],
            stats: { totalClicks: 0, totalLogins: 0, successfulLogins: 0, failedLogins: 0, totalActivities: 0, todayClicks: 0, uniqueIPs: 0 },
            success: null,
            error: 'Loglar yüklenemedi',
            filters: { type: 'all', limit: 15, search: '', page: 1, totalPages: 1 }
        });
    }
});

app.get('/hradmin/api/logs/:linkId', requireAuth, requireAjax, async (req, res) => {
    const linkId = parseInt(req.params.linkId);

    if (isNaN(linkId)) {
        return res.status(400).json({ error: 'Geçersiz link ID' });
    }

    const limit = parseInt(req.query.limit) || 15;
    const offset = parseInt(req.query.offset) || 0;

    try {
        await dbRun(`
            UPDATE click_logs 
            SET country = (SELECT country FROM ip_cache WHERE ip_cache.ip = click_logs.ip),
                country_code = (SELECT country_code FROM ip_cache WHERE ip_cache.ip = click_logs.ip),
                city = (SELECT city FROM ip_cache WHERE ip_cache.ip = click_logs.ip),
                region = (SELECT region FROM ip_cache WHERE ip_cache.ip = click_logs.ip),
                timezone = (SELECT timezone FROM ip_cache WHERE ip_cache.ip = click_logs.ip),
                ll = (SELECT ll FROM ip_cache WHERE ip_cache.ip = click_logs.ip)
            WHERE link_id = ? AND (country IS NULL OR country = '' OR country = 'Bilinmiyor')
              AND EXISTS (SELECT 1 FROM ip_cache WHERE ip_cache.ip = click_logs.ip AND country IS NOT NULL AND country != '')
        `, [linkId]).catch(() => { });

        const logs = await dbAll(`
            SELECT c.id, c.link_id, c.slug, c.target_url, c.ip, c.referer, c.user_agent, 
                   c.browser, c.browser_version, c.os, c.os_version, c.device_type, c.language, 
                   COALESCE(ic.country, c.country) as country, 
                   COALESCE(ic.country_code, c.country_code) as country_code, 
                   COALESCE(ic.city, c.city) as city, 
                   COALESCE(ic.region, c.region) as region, 
                   COALESCE(ic.timezone, c.timezone) as timezone, 
                   COALESCE(ic.ll, c.ll) as ll,
                   c.created_at
            FROM click_logs c 
            LEFT JOIN ip_cache ic ON c.ip = ic.ip 
            WHERE c.link_id = ? 
            ORDER BY c.created_at DESC
            LIMIT ? OFFSET ?
        `, [linkId, limit, offset]);

        if (logs.length > 0) {
            logs.forEach(log => {
                if (!log.country || log.country === 'Bilinmiyor') {
                    getGeoInfo(log.ip).catch(() => { });
                }
            });
        }

        res.json(logs);
    } catch (err) {
        console.error('Log fetch error:', err);
        res.status(500).json({ error: 'Loglar yüklenemedi' });
    }
});

app.post('/hradmin/links', requireAuth, requireAdmin, async (req, res) => {
    const { slug, targetUrl, title } = req.body;

    if (!slug || !targetUrl) {
        res.cookie('flash_error', 'Slug ve hedef URL gerekli', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/links');
    }

    if (!isValidUrl(targetUrl) || !isSafeUrl(targetUrl)) {
        res.cookie('flash_error', 'Geçersiz veya güvensiz URL', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/links');
    }

    const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-_]/g, '');

    if (cleanSlug.length < 1) {
        res.cookie('flash_error', 'Geçersiz slug', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/links');
    }

    const reserved = ['hradmin', 'api', 'admin', 'static', 'public', 'login', 'logout'];
    if (reserved.includes(cleanSlug)) {
        res.cookie('flash_error', 'Bu isim rezerve edilmiş', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/links');
    }

    try {
        const existing = await dbGet('SELECT * FROM links WHERE slug = ?', [cleanSlug]);
        if (existing) {
            res.cookie('flash_error', 'Bu kısa isim zaten kullanılıyor', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/links');
        }

        const result = await dbRun('INSERT INTO links (slug, target_url, title) VALUES (?, ?, ?)', [cleanSlug, targetUrl, title || '']);
        await logActivity(req, 'create', 'link', 'link', result.lastID, cleanSlug, `Hedef: ${targetUrl}`);
        res.cookie('flash_success', 'Link oluşturuldu', { httpOnly: true, path: '/' });
    } catch (err) {
        res.cookie('flash_error', 'Link oluşturulamadı', { httpOnly: true, path: '/' });
    }

    res.redirect('/hradmin/links');
});

app.get('/hradmin/links/:id/edit', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) {
            res.cookie('flash_error', 'Geçersiz link ID', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/links');
        }

        const link = await dbGet('SELECT * FROM links WHERE id = ?', [id]);
        if (!link) {
            res.cookie('flash_error', 'Link bulunamadı', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/links');
        }
        res.render('edit-link', { link });
    } catch (err) {
        res.cookie('flash_error', 'Link yüklenemedi', { httpOnly: true, path: '/' });
        res.redirect('/hradmin/links');
    }
});

app.post('/hradmin/links/:id/edit', requireAuth, requireAdmin, async (req, res) => {
    const { slug, targetUrl, title } = req.body;
    const id = parseInt(req.params.id);

    if (isNaN(id)) {
        res.cookie('flash_error', 'Geçersiz link ID', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/links');
    }

    if (!isValidUrl(targetUrl) || !isSafeUrl(targetUrl)) {
        res.cookie('flash_error', 'Geçersiz veya güvensiz URL', { httpOnly: true, path: '/' });
        return res.redirect(`/hradmin/links/${id}/edit`);
    }

    try {
        const link = await dbGet('SELECT * FROM links WHERE id = ?', [id]);
        if (!link) {
            res.cookie('flash_error', 'Link bulunamadı', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/links');
        }

        const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-_]/g, '');
        const reserved = ['hradmin', 'api', 'admin', 'static', 'public', 'login', 'logout'];

        if (reserved.includes(cleanSlug)) {
            res.cookie('flash_error', 'Bu isim rezerve edilmiş', { httpOnly: true, path: '/' });
            return res.redirect(`/hradmin/links/${id}/edit`);
        }

        const existing = await dbGet('SELECT * FROM links WHERE slug = ? AND id != ?', [cleanSlug, id]);
        if (existing) {
            res.cookie('flash_error', 'Bu kısa isim zaten kullanılıyor', { httpOnly: true, path: '/' });
            return res.redirect(`/hradmin/links/${id}/edit`);
        }

        await dbRun('UPDATE links SET slug = ?, target_url = ?, title = ? WHERE id = ?', [cleanSlug, targetUrl, title || '', id]);
        await logActivity(req, 'update', 'link', 'link', id, cleanSlug, `Eski: ${link.slug} -> Yeni: ${cleanSlug}`);
        res.cookie('flash_success', 'Link güncellendi', { httpOnly: true, path: '/' });
    } catch (err) {
        res.cookie('flash_error', 'Link güncellenemedi', { httpOnly: true, path: '/' });
    }

    res.redirect('/hradmin/links');
});

app.post('/hradmin/links/:id/delete', requireAuth, requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);

    if (isNaN(id)) {
        res.cookie('flash_error', 'Geçersiz link ID', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/links');
    }

    try {
        const link = await dbGet('SELECT * FROM links WHERE id = ?', [id]);
        if (!link) {
            res.cookie('flash_error', 'Link bulunamadı', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/links');
        }

        await dbRun('DELETE FROM links WHERE id = ?', [id]);
        await logActivity(req, 'delete', 'link', 'link', id, link.slug, `Silinen hedef: ${link.target_url}`);
        res.cookie('flash_success', 'Link silindi', { httpOnly: true, path: '/' });
    } catch (err) {
        res.cookie('flash_error', 'Link silinemedi', { httpOnly: true, path: '/' });
    }

    res.redirect('/hradmin/links');
});

app.get('/hradmin/settings', requireAuth, requireAdmin, async (req, res) => {
    const domainSetting = await getSetting('domain');
    const users = await dbAll('SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at DESC');
    res.render('dashboard', {
        page: 'settings',
        domain: DOMAIN,
        settings: { domain: domainSetting },
        users,
        currentUserId: req.user ? req.user.userId : null,
        success: res.locals.success,
        error: res.locals.error
    });
});

app.post('/hradmin/settings', requireAuth, requireAdmin, async (req, res) => {
    const { domain: newDomain } = req.body;

    try {
        if (newDomain) {
            if (!isValidUrl(newDomain) || !isSafeUrl(newDomain)) {
                res.cookie('flash_error', 'Geçersiz yönlendirme URL\'si', { httpOnly: true, path: '/' });
                return res.redirect('/hradmin/settings');
            }
            await setSetting('domain', newDomain);

            const envDomain = process.env.DOMAIN;
            if (newDomain !== envDomain) {
                global.domainError = { env: envDomain, db: newDomain };
            } else {
                delete global.domainError;
            }

            await logActivity(req, 'update', 'settings', 'settings', null, 'domain', `Yeni değer: ${newDomain}`);
            res.cookie('flash_success', 'Ayarlar güncellendi', { httpOnly: true, path: '/' });
        }
    } catch (err) {
        res.cookie('flash_error', 'Ayarlar güncellenemedi', { httpOnly: true, path: '/' });
    }

    res.redirect('/hradmin/settings');
});

app.post('/hradmin/users/create', requireAuth, requireAdmin, async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        res.cookie('flash_error', 'Kullanıcı adı ve şifre gerekli', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/users');
    }

    if (password.length < 8) {
        res.cookie('flash_error', 'Şifre en az 8 karakter olmalı', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/users');
    }

    const cleanUsername = username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (cleanUsername.length < 3) {
        res.cookie('flash_error', 'Kullanıcı adı en az 3 karakter olmalı', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/users');
    }

    try {
        const existing = await dbGet('SELECT id FROM users WHERE username = ?', [cleanUsername]);
        if (existing) {
            res.cookie('flash_error', 'Bu kullanıcı adı zaten alınmış', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/users');
        }

        const hashedPassword = await hashPassword(password);
        const result = await dbRun('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [cleanUsername, hashedPassword, role || 'user']);
        await logActivity(req, 'create', 'user', 'user', result.lastID, cleanUsername, `Rol: ${role || 'user'}`);

        res.cookie('flash_success', `Kullanıcı "${cleanUsername}" oluşturuldu`, { httpOnly: true, path: '/' });
    } catch (err) {
        console.error('User create error:', err);
        res.cookie('flash_error', 'Kullanıcı oluşturulamadı', { httpOnly: true, path: '/' });
    }

    res.redirect('/hradmin/users');
});

app.post('/hradmin/users/:id/delete', requireAuth, requireAdmin, async (req, res) => {
    const userId = parseInt(req.params.id);

    if (isNaN(userId)) {
        res.cookie('flash_error', 'Geçersiz kullanıcı ID', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/users');
    }

    if (userId === req.user.userId) {
        res.cookie('flash_error', 'Kendinizi silemezsiniz', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/users');
    }

    try {
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
        if (!user) {
            res.cookie('flash_error', 'Kullanıcı bulunamadı', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/users');
        }

        const adminCount = await dbGet('SELECT COUNT(*) as count FROM users WHERE role = ?', ['admin']);
        if (user.role === 'admin' && adminCount.count <= 1) {
            res.cookie('flash_error', 'Son admin kullanıcısını silemezsiniz', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/users');
        }

        await dbRun('DELETE FROM users WHERE id = ?', [userId]);
        await logActivity(req, 'delete', 'user', 'user', userId, user.username, `Rol: ${user.role}`);
        res.cookie('flash_success', `Kullanıcı "${user.username}" silindi`, { httpOnly: true, path: '/' });
    } catch (err) {
        console.error('User delete error:', err);
        res.cookie('flash_error', 'Kullanıcı silinemedi', { httpOnly: true, path: '/' });
    }

    res.redirect('/hradmin/users');
});

app.post('/hradmin/users/:id/password', requireAuth, requireAdmin, async (req, res) => {
    const userId = parseInt(req.params.id);
    const { newPassword } = req.body;

    if (isNaN(userId)) {
        res.cookie('flash_error', 'Geçersiz kullanıcı ID', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/users');
    }

    if (!newPassword || newPassword.length < 8) {
        res.cookie('flash_error', 'Şifre en az 8 karakter olmalı', { httpOnly: true, path: '/' });
        return res.redirect('/hradmin/users');
    }

    try {
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
        if (!user) {
            res.cookie('flash_error', 'Kullanıcı bulunamadı', { httpOnly: true, path: '/' });
            return res.redirect('/hradmin/users');
        }

        const hashedPassword = await hashPassword(newPassword);
        await dbRun('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
        await logActivity(req, 'update', 'user', 'user', userId, user.username, 'Şifre değiştirildi');
        res.cookie('flash_success', `"${user.username}" kullanıcısının şifresi değiştirildi`, { httpOnly: true, path: '/' });
    } catch (err) {
        console.error('Password change error:', err);
        res.cookie('flash_error', 'Şifre değiştirilemedi', { httpOnly: true, path: '/' });
    }

    res.redirect('/hradmin/users');
});

app.get('/:slug', async (req, res) => {
    const { slug } = req.params;
    const clientIP = getClientIP(req);

    const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-_]/g, '');

    try {
        const link = await dbGet('SELECT * FROM links WHERE slug = ?', [cleanSlug]);

        if (link) {
            const userAgent = req.headers['user-agent'] || '';
            const referer = req.headers['referer'] || req.headers['referrer'] || 'direct';
            const language = req.headers['accept-language']?.split(',')[0] || 'unknown';
            const deviceInfo = parseUserAgent(userAgent);

            getGeoInfo(clientIP).then(async (geo) => {
                try {
                    await dbRun(`
                        INSERT INTO click_logs 
                        (link_id, slug, target_url, ip, referer, user_agent, browser, browser_version, os, os_version, device_type, language, country, country_code, city, region, timezone, ll)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        link.id, cleanSlug, link.target_url, clientIP, referer, userAgent,
                        deviceInfo.browser, deviceInfo.browserVersion, deviceInfo.os, deviceInfo.osVersion,
                        deviceInfo.deviceType, language, geo.country || null, geo.country_code || null, geo.city || null,
                        geo.region || null, geo.timezone || null, geo.ll || null
                    ]);

                    await dbRun('UPDATE links SET clicks = clicks + 1, last_clicked_at = CURRENT_TIMESTAMP WHERE id = ?', [link.id]);

                    const location = geo.city ? `${geo.city}, ${geo.country || '??'}` : (geo.country || 'Bilinmiyor');
                    console.log(`🔗 Link tıklandı: /${cleanSlug} | IP: ${clientIP} | Konum: ${location}`);
                } catch (logErr) {
                    console.error('Background logging error:', logErr);
                }
            });

            return res.redirect(302, link.target_url);
        }
    } catch (err) {
        console.error('Redirect error:', err);
    }

    const domainSetting = await getSetting('domain');
    res.redirect(302, domainSetting || DOMAIN);
});

app.use((req, res) => {
    res.status(404).json({ error: 'Sayfa bulunamadı' });
});

app.use((err, req, res, next) => {
    console.error(`🔥 KRİTİK HATA (${req.method} ${req.url}):`, err.stack);

    if (req.xhr || req.headers.accept?.includes('application/json') || req.path.startsWith('/api/') || req.path.startsWith('/hradmin/api/')) {
        return res.status(500).json({ error: 'Sunucu tarafında beklenmeyen bir hata oluştu.' });
    }

    res.status(500).send(`
        <body style="background: #0b0c10; color: #fff; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
            <div style="text-align: center; padding: 3rem; border: 1px solid #1f2833; border-radius: 16px; background: rgba(31, 40, 51, 0.3); max-width: 500px; backdrop-filter: blur(10px);">
                <h1 style="color: #ef4444; margin-top: 0;">🔥 500 - Sunucu Hatası</h1>
                <p style="color: #94a3b8; margin-bottom: 2rem;">Beklenmeyen bir hata oluştu. Lütfen daha sonra tekrar deneyin.</p>
                <a href="/" style="display: inline-block; padding: 12px 24px; background: #4facfe; color: #0b0c10; text-decoration: none; border-radius: 8px; font-weight: bold; transition: opacity 0.2s;">Ana Sayfaya Dön</a>
            </div>
        </body>
    `);
});


app.listen(PORT, () => {
    console.log(`----------------------------------------------`);
    console.log(`       HUNTERROCK GO`);
    console.log(`      Link Kısaltma Sistemi`);
    console.log(`----------------------------------------------`);
    console.log(`🚀 Hunterrock GO çalışıyor: ${process.env.DOMAIN}`);
    console.log(`📊 Admin Panel: ${process.env.DOMAIN}/hradmin`);
    console.log(`💾 Veritabanı: SQLite (hrgo.db)`);
    console.log(`----------------------------------------------`);
});

process.on('SIGINT', () => {
    db.close();
    process.exit(0);
});

process.on('SIGTERM', () => {
    db.close();
    process.exit(0);
});
