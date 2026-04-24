#!/usr/bin/env node

// ============================================
// Hunterrock GO - Kurulum Scripti
// ============================================
// Kullanım: node setup.js
// Bu script admin bilgileri, domain ve port'u sorar,
// .env dosyasını oluşturur ve veritabanında admin kullanıcısını hazırlar.

const readline = require('readline');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function ask(question, defaultValue = '') {
    const suffix = defaultValue ? ` (varsayılan: ${defaultValue})` : '';
    return new Promise((resolve) => {
        rl.question(`${question}${suffix}: `, (answer) => {
            resolve(answer.trim() || defaultValue);
        });
    });
}

function askHidden(question) {
    return new Promise((resolve) => {
        const stdin = process.stdin;
        const stdout = process.stdout;

        stdout.write(question + ': ');

        const originalRawMode = stdin.isRaw;
        if (stdin.isTTY) {
            stdin.setRawMode(true);
        }

        let password = '';
        const onData = (char) => {
            const c = char.toString('utf8');

            switch (c) {
                case '\n':
                case '\r':
                case '\u0004':
                    if (stdin.isTTY) stdin.setRawMode(originalRawMode);
                    stdin.removeListener('data', onData);
                    stdout.write('\n');
                    resolve(password);
                    break;
                case '\u0003':
                    if (stdin.isTTY) stdin.setRawMode(originalRawMode);
                    console.log('\n❌ Kurulum iptal edildi.');
                    process.exit(0);
                    break;
                case '\u007f':
                case '\b':
                    if (password.length > 0) {
                        password = password.slice(0, -1);
                        stdout.clearLine(0);
                        stdout.cursorTo(0);
                        stdout.write(question + ': ' + '*'.repeat(password.length));
                    }
                    break;
                default:
                    if (c.length === 1 && c >= ' ') {
                        password += c;
                        stdout.write('*');
                    }
                    break;
            }
        };

        stdin.on('data', onData);
    });
}

function validatePassword(password) {
    const errors = [];
    if (password.length < 8) errors.push('En az 8 karakter olmalı');
    if (!/[A-Z]/.test(password)) errors.push('En az 1 büyük harf içermeli');
    if (!/[a-z]/.test(password)) errors.push('En az 1 küçük harf içermeli');
    if (!/[0-9]/.test(password)) errors.push('En az 1 rakam içermeli');
    return errors;
}

function validateDomain(domain) {
    try {
        const url = new URL(domain);
        return url.protocol === 'https:' || url.protocol === 'http:';
    } catch {
        return false;
    }
}

async function main() {
    console.log('');
    console.log('╔══════════════════════════════════════════╗');
    console.log('║     🔗 Hunterrock GO - Kurulum Sihirbazı     ║');
    console.log('╚══════════════════════════════════════════╝');
    console.log('');

    // ============================================
    // Bağımlılıkları Kontrol Et ve Yükle
    // ============================================
    console.log('── 📦 Bağımlılıklar Kontrol Ediliyor... ──────');

    const checkDeps = () => {
        try {
            require.resolve('express');
            require.resolve('sqlite3');
            require.resolve('bcryptjs');
            require.resolve('geoip-lite');
            require.resolve('jsonwebtoken');
            return true;
        } catch (e) {
            return false;
        }
    };

    if (!checkDeps() || !fs.existsSync(path.join(__dirname, 'node_modules'))) {
        try {
            console.log('  ℹ️  Eksik paketler tespit edildi, yükleniyor...');
            execSync('npm install', { stdio: 'inherit' });
            console.log('  ✅ Paketler başarıyla yüklendi.');
        } catch (err) {
            console.error('  ❌ Paket yükleme hatası:', err.message);
            console.log('  Devam ediliyor, ancak eksik paketler varsa kurulum başarısız olabilir.');
        }
    } else {
        console.log('  ✅ Tüm bağımlılıklar zaten yüklü.');
    }
    console.log('');

    const envPath = path.join(__dirname, '.env');
    const dbPath = path.join(__dirname, 'hrgo.db');

    if (fs.existsSync(envPath)) {
        const overwrite = await ask('⚠️  .env dosyası zaten mevcut. Üzerine yazmak ister misiniz? (e/h)', 'h');
        if (overwrite.toLowerCase() !== 'e') {
            console.log('❌ Kurulum iptal edildi. Mevcut .env dosyası korundu.');
            rl.close();
            process.exit(0);
        }
        console.log('');
    }

    // ============================================
    // Admin Bilgileri
    // ============================================
    console.log('── 👤 Admin Bilgileri ──────────────────────');
    console.log('');

    let username = await ask('  Admin kullanıcı adı', 'admin');
    username = username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    while (username.length < 3) {
        console.log('  ❌ Kullanıcı adı en az 3 karakter olmalı (harf, rakam, tire, alt çizgi)');
        username = await ask('  Admin kullanıcı adı', 'admin');
        username = username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    }

    let password = '';
    let passwordValid = false;
    while (!passwordValid) {
        password = await askHidden('  Admin şifresi');
        const errors = validatePassword(password);
        if (errors.length > 0) {
            console.log('  ❌ Şifre gereksinimleri:');
            errors.forEach(e => console.log(`     • ${e}`));
        } else {
            const confirm = await askHidden('  Şifreyi tekrar girin');
            if (password !== confirm) {
                console.log('  ❌ Şifreler eşleşmiyor. Tekrar deneyin.');
            } else {
                passwordValid = true;
            }
        }
    }

    console.log('');

    // ============================================
    // Domain & Port
    // ============================================
    console.log('── 🌐 Sunucu Ayarları ─────────────────────');
    console.log('');

    let domain = await ask('  Domain (https:// ile)', 'https://go.example.com');
    while (!validateDomain(domain)) {
        console.log('  ❌ Geçersiz domain. https://... veya http://... formatında girin.');
        domain = await ask('  Domain (https:// ile)', 'https://go.example.com');
    }
    domain = domain.replace(/\/+$/, '');

    const port = await ask('  Port', '3000');
    const portNum = parseInt(port);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        console.log('  ⚠️  Geçersiz port, varsayılan 3000 kullanılıyor.');
    }
    const finalPort = (isNaN(portNum) || portNum < 1 || portNum > 65535) ? '3000' : port;

    console.log('');

    // ============================================
    // Otomatik Değerler
    // ============================================
    const sessionSecret = crypto.randomBytes(64).toString('hex');

    // ============================================
    // Özet
    // ============================================
    console.log('── 📋 Kurulum Özeti ───────────────────────');
    console.log('');
    console.log(`  👤 Admin       : ${username}`);
    console.log(`  🔒 Şifre       : ${'*'.repeat(password.length)}`);
    console.log(`  🌐 Domain      : ${domain}`);
    console.log(`  🔌 Port        : ${finalPort}`);
    console.log(`  🏗️  Ortam       : production`);
    console.log(`  🔑 Session Key : ${sessionSecret.substring(0, 16)}...`);
    console.log('');

    const confirm = await ask('  Bu ayarlarla devam etmek istiyor musunuz? (e/h)', 'e');
    if (confirm.toLowerCase() !== 'e') {
        console.log('❌ Kurulum iptal edildi.');
        rl.close();
        process.exit(0);
    }

    console.log('');
    console.log('── ⚙️  Kurulum Yapılıyor... ────────────────');
    console.log('');

    // ============================================
    // .env Dosyasını Oluştur
    // ============================================
    const envContent = `# Hunterrock GO - Yapılandırma
# Bu dosya setup.js tarafından otomatik oluşturuldu.
# Tarih: ${new Date().toISOString()}

# Ortam
NODE_ENV=production

# Port
PORT=${finalPort}

# Session Secret
SESSION_SECRET=${sessionSecret}

# Domain
DOMAIN=${domain}
`;

    fs.writeFileSync(envPath, envContent, 'utf-8');
    console.log('  ✅ .env dosyası oluşturuldu');

    // ============================================
    // Veritabanında Admin Kullanıcısını Oluştur
    // ============================================
    try {
        const bcrypt = require('bcryptjs');
        const sqlite3 = require('sqlite3').verbose();

        const db = new sqlite3.Database(dbPath);

        await new Promise((resolve, reject) => {
            db.serialize(() => {
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

                db.run("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
                db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('domain', ?)", [domain]);

                resolve();
            });
        });

        const hashedPassword = await bcrypt.hash(password, 12);

        await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
                if (err) return reject(err);

                if (row) {
                    db.run('UPDATE users SET password = ?, role = ? WHERE username = ?',
                        [hashedPassword, 'admin', username], (err) => {
                            if (err) reject(err);
                            else {
                                console.log(`  ✅ Admin kullanıcısı güncellendi: ${username}`);
                                resolve();
                            }
                        });
                } else {
                    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                        [username, hashedPassword, 'admin'], (err) => {
                            if (err) reject(err);
                            else {
                                console.log(`  ✅ Admin kullanıcısı oluşturuldu: ${username}`);
                                resolve();
                            }
                        });
                }
            });
        });

        db.close();
    } catch (err) {
        console.error('  ❌ Veritabanı hatası:', err.message);
        console.log('  ℹ️  .env dosyası oluşturuldu, sunucuyu başlattığınızda admin otomatik oluşacak.');
    }

    // ============================================
    // Tamamlandı
    // ============================================
    console.log('');
    console.log('╔══════════════════════════════════════════╗');
    console.log('║         ✅ Kurulum Tamamlandı!           ║');
    console.log('╚══════════════════════════════════════════╝');
    console.log('');
    console.log('  Sunucuyu başlatmak için:');
    console.log('    npm start');
    console.log('');
    console.log(`  Admin paneli: ${domain}/hradmin`);
    console.log(`  Kullanıcı adı: ${username}`);
    console.log('');

    rl.close();
    process.exit(0);
}

main().catch(err => {
    console.error('❌ Kurulum hatası:', err);
    rl.close();
    process.exit(1);
});
