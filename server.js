/**
 * Kasaly — Node.js / Express API (MongoDB Atlas) v6.0
 * ─────────────────────────────────────────────────────
 * Değişiklikler:
 *   - helmet ile HTTP güvenlik başlıkları
 *   - cookie secure production'da otomatik true
 *   - /api/users sadece admin erişebilir (KVKK)
 *   - userdata 4MB sınırı + txn sayı limiti (5000)
 *   - Şifre validasyonu ayrı helper'a çekildi (DRY)
 *   - /api/admin/reset-password (admin'in şifre sıfırlaması)
 *   - /api/delete-account (kullanıcı kendi hesabını siler)
 *   - /api/stats cache (1 dakika) — her istek DB scan yapmasın
 *   - Tüm DB hatalarında leak olmayan safe error mesajları
 */

require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || 'kasaly';
const SECRET = process.env.SESSION_SECRET || 'kasaly-secret-change-this';
const ADMIN_USER = process.env.ADMIN_USERNAME || 'kasalyadmin2026@gmail.com';
const IS_PROD = process.env.NODE_ENV === 'production';

/* ─── MongoDB client ─── */
let db;
async function connectDB() {
    const client = new MongoClient(MONGO_URI, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000
    });
    await client.connect();
    db = client.db(DB_NAME);
    console.log('[MongoDB] Connected to', DB_NAME);
    await db.collection('profiles').createIndex({ username: 1 }, { unique: true });
    await db.collection('profiles').createIndex({ email: 1 }, { sparse: true });
}

/* ─── Helpers ─── */
function normalizeUsername(u) { return u.trim().toLowerCase(); }

function isAdmin(req) {
    return req.session && req.session.username === ADMIN_USER;
}
function requireAuth(req, res, next) {
    if (!req.session || !req.session.uid)
        return res.status(401).json({ error: 'Oturum açmanız gerekiyor' });
    next();
}
function requireAdmin(req, res, next) {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Yetkisiz erişim' });
    next();
}

/** Şifre kuralları — tek yerde tanımlı */
function validatePassword(pw) {
    if (!pw || pw.length < 8) return 'Şifre en az 8 karakter olmalıdır';
    if (!/[A-Z]/.test(pw)) return 'Şifre en az 1 büyük harf içermelidir';
    if (!/[a-z]/.test(pw)) return 'Şifre en az 1 küçük harf içermelidir';
    if (!/[0-9]/.test(pw)) return 'Şifre en az 1 rakam içermelidir';
    if (!/[^A-Za-z0-9]/.test(pw)) return 'Şifre en az 1 özel karakter içermelidir';
    return null; // geçerli
}

/** Kullanıcıdan dışarıya güvenli veri — şifre hash'i asla */
function safeUser(p) {
    return {
        uid: p._id,
        username: p.username,
        fullname: p.fullname,
        accType: p.accType,
        company: p.company || '',
        phone: p.phone || '',
        birthdate: p.birthdate || '',
        email: p.email || '',
        securityQuestion: p.securityQuestion || '',
        profileComplete: p.profileComplete || false,
        banned: p.banned || false,
        banReason: p.banReason || '',
        createdAt: p.createdAt || ''
    };
}

/* ─── Stats cache (1 dak) ─── */
let _statsCache = null;
let _statsCacheTime = 0;
async function getStats() {
    const now = Date.now();
    if (_statsCache && now - _statsCacheTime < 60_000) return _statsCache;
    const userCount = await db.collection('profiles').countDocuments();
    const allData = await db.collection('userdata').find({}, { projection: { 'data.txns': 1, 'data.goals': 1 } }).toArray();
    let txnCount = 0, goalCount = 0;
    for (const row of allData) {
        const d = row.data || {};
        if (Array.isArray(d.txns)) txnCount += d.txns.length;
        if (Array.isArray(d.goals)) goalCount += d.goals.length;
    }
    _statsCache = { users: userCount, txns: txnCount, goals: goalCount };
    _statsCacheTime = now;
    return _statsCache;
}

/* ─── Middleware ─── */
app.set('trust proxy', 1); // Render/Railway gibi proxy arkasında çalışmak için

app.use(express.json({ limit: '4mb' }));

/* Güvenlik header'ları (helmet olmadan manuel) */
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (IS_PROD) {
        res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    }
    next();
});

/* Rate limiter — login/register */
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Çok fazla istek gönderildi. 15 dakika sonra tekrar deneyin.' },
    standardHeaders: true,
    legacyHeaders: false
});

/* Genel API limiti */
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    message: { error: 'Çok fazla istek. Bir dakika bekleyin.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', apiLimiter);

/* CORS */
const ALLOWED_ORIGINS = [
    process.env.FRONTEND_ORIGIN,
    process.env.FRONTEND_ORIGIN_2,
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
].filter(Boolean);

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        return callback(new Error('CORS: izin verilmeyen origin: ' + origin));
    },
    credentials: true
}));

/* Session */
app.use(session({
    secret: SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGO_URI,
        dbName: DB_NAME,
        collectionName: 'sessions',
        ttl: 30 * 24 * 60 * 60 // 30 gün
    }),
    cookie: {
        httpOnly: true,
        secure: IS_PROD,      // Production'da HTTPS zorunlu
        sameSite: IS_PROD ? 'none' : 'lax',  // Cross-origin cookie production'da
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}));

/* ══════════════════════════════════════════════════
   AUTH
══════════════════════════════════════════════════ */

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, password, fullname, accType, company, phone, birthdate, email, securityQuestion, securityAnswerHash } = req.body;
        if (!username || !password || !fullname)
            return res.status(400).json({ error: 'Zorunlu alanlar eksik' });
        if (username.length < 3 || username.length > 50)
            return res.status(400).json({ error: 'Kullanıcı adı 3-50 karakter arasında olmalıdır' });

        const pwErr = validatePassword(password);
        if (pwErr) return res.status(400).json({ error: pwErr });

        const col = db.collection('profiles');
        const existing = await col.findOne({ username: normalizeUsername(username) });
        if (existing) return res.status(409).json({ error: 'Bu kullanıcı adı zaten kullanılmaktadır' });

        const passwordHash = await bcrypt.hash(password, 12);
        const uid = new ObjectId().toHexString();

        await col.insertOne({
            _id: uid,
            username: normalizeUsername(username),
            fullname,
            accType: accType || 'bireysel',
            company: company || '',
            phone: phone || '',
            birthdate: birthdate || '',
            email: email || '',
            securityQuestion: securityQuestion || '',
            securityAnswerHash: securityAnswerHash || '',
            profileComplete: !!(phone && birthdate && fullname),
            banned: false,
            banReason: '',
            passwordHash,
            createdAt: new Date().toISOString()
        });

        await db.collection('userdata').insertOne({ _id: uid, data: {} });
        // Stats cache'i sıfırla
        _statsCache = null;
        res.json({ ok: true, uid });
    } catch (e) {
        console.error('[register]', e);
        res.status(500).json({ error: 'Kayıt işlemi başarısız' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Kullanıcı adı ve şifre zorunludur' });

        const col = db.collection('profiles');
        const user = await col.findOne({ username: normalizeUsername(username) });

        // Timing attack koruması: kullanıcı bulunamasa bile bcrypt çalıştır
        const dummyHash = '$2a$12$invalidhashfortimingprotectiononly000000000000000000000';
        const match = user ? await bcrypt.compare(password, user.passwordHash) : await bcrypt.compare(password, dummyHash).then(() => false);

        if (!user || !match)
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı' });

        if (user.banned) {
            const reason = user.banReason ? ` Sebep: ${user.banReason}` : '';
            return res.status(403).json({ error: `Hesabınız yetkili tarafından yasaklanmıştır.${reason}` });
        }

        req.session.uid = user._id;
        req.session.username = user.username;

        res.json({ ok: true, user: safeUser(user) });
    } catch (e) {
        console.error('[login]', e);
        res.status(500).json({ error: 'Giriş sırasında hata oluştu' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.clearCookie('connect.sid').json({ ok: true }));
});

app.get('/api/session', async (req, res) => {
    if (!req.session?.uid) return res.json({ loggedIn: false });
    try {
        const user = await db.collection('profiles').findOne({ _id: req.session.uid });
        if (!user) return res.json({ loggedIn: false });
        res.json({ loggedIn: true, user: safeUser(user) });
    } catch (e) {
        res.json({ loggedIn: false });
    }
});

/* ══════════════════════════════════════════════════
   PROFILE
══════════════════════════════════════════════════ */

app.get('/api/profile', requireAuth, async (req, res) => {
    try {
        const user = await db.collection('profiles').findOne({ _id: req.session.uid });
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        res.json(safeUser(user));
    } catch (e) {
        res.status(500).json({ error: 'Profil alınamadı' });
    }
});

app.put('/api/profile', requireAuth, async (req, res) => {
    try {
        const allowed = ['fullname', 'phone', 'birthdate', 'email', 'company', 'sector', 'taxNo', 'profileComplete'];
        const update = {};
        for (const k of allowed) {
            if (req.body[k] !== undefined) update[k] = req.body[k];
        }
        if (Object.keys(update).length === 0)
            return res.status(400).json({ error: 'Güncellenecek alan bulunamadı' });
        await db.collection('profiles').updateOne({ _id: req.session.uid }, { $set: update });
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Profil güncellenemedi' });
    }
});

/* ══════════════════════════════════════════════════
   PASSWORD
══════════════════════════════════════════════════ */

app.post('/api/verify-password', requireAuth, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });
        const user = await db.collection('profiles').findOne({ _id: req.session.uid });
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const match = await bcrypt.compare(password, user.passwordHash);
        res.json({ ok: match });
    } catch (e) {
        res.status(500).json({ error: 'Doğrulama hatası' });
    }
});

app.post('/api/reset-password', requireAuth, async (req, res) => {
    try {
        const { newPassword } = req.body;
        const pwErr = validatePassword(newPassword);
        if (pwErr) return res.status(400).json({ error: pwErr });
        const passwordHash = await bcrypt.hash(newPassword, 12);
        await db.collection('profiles').updateOne({ _id: req.session.uid }, { $set: { passwordHash } });
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Şifre güncellenemedi' });
    }
});

/* ══════════════════════════════════════════════════
   HESAP SİLME (kullanıcının kendi isteğiyle)
══════════════════════════════════════════════════ */

app.post('/api/delete-account', requireAuth, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Şifre gerekli' });
        const user = await db.collection('profiles').findOne({ _id: req.session.uid });
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(401).json({ error: 'Şifre hatalı' });

        const uid = req.session.uid;
        await db.collection('userdata').deleteOne({ _id: uid });
        await db.collection('profiles').deleteOne({ _id: uid });
        await db.collection('sessions').deleteMany({ 'session.uid': uid });
        _statsCache = null;
        req.session.destroy(() => res.json({ ok: true }));
    } catch (e) {
        res.status(500).json({ error: 'Hesap silinemedi' });
    }
});

/* ══════════════════════════════════════════════════
   USER DATA
══════════════════════════════════════════════════ */

const MAX_TXNS = 5000;

app.get('/api/userdata', requireAuth, async (req, res) => {
    try {
        const row = await db.collection('userdata').findOne({ _id: req.session.uid });
        res.json(row ? row.data : {});
    } catch (e) {
        res.status(500).json({ error: 'Veri alınamadı' });
    }
});

app.put('/api/userdata', requireAuth, async (req, res) => {
    try {
        const data = req.body.data;
        if (!data || typeof data !== 'object')
            return res.status(400).json({ error: 'Geçersiz veri formatı' });

        // İşlem sayısı güvenlik sınırı
        if (Array.isArray(data.txns) && data.txns.length > MAX_TXNS)
            return res.status(400).json({ error: `Maksimum ${MAX_TXNS} işlem kaydedilebilir` });

        await db.collection('userdata').updateOne(
            { _id: req.session.uid },
            { $set: { data, updatedAt: new Date().toISOString() } },
            { upsert: true }
        );
        // Stats cache yenile
        _statsCache = null;
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Veri kaydedilemedi' });
    }
});

/* ══════════════════════════════════════════════════
   USERS LİSTESİ — SADECE ADMİN
══════════════════════════════════════════════════ */

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const profiles = await db.collection('profiles')
            .find({}, { projection: { passwordHash: 0, securityAnswerHash: 0 } })
            .toArray();
        res.json(profiles.map(safeUser));
    } catch (e) {
        res.status(500).json({ error: 'Kullanıcılar alınamadı' });
    }
});

/* ══════════════════════════════════════════════════
   PUBLIC STATS (cached)
══════════════════════════════════════════════════ */

app.get('/api/stats', async (req, res) => {
    try {
        res.json(await getStats());
    } catch (e) {
        res.status(500).json({ error: 'İstatistikler alınamadı' });
    }
});

/* ══════════════════════════════════════════════════
   GÜVENLİK SORUSU / ŞİFRE SIFIRLAMA
══════════════════════════════════════════════════ */

app.get('/api/security-question/:username', async (req, res) => {
    try {
        const user = await db.collection('profiles').findOne(
            { username: normalizeUsername(req.params.username) },
            { projection: { securityQuestion: 1 } }
        );
        // Kullanıcı bulunamasa bile aynı hata — kullanıcı enumeration engeli
        if (!user || !user.securityQuestion)
            return res.status(404).json({ error: 'Bu hesap için güvenlik sorusu tanımlı değil' });
        res.json({ question: user.securityQuestion });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

app.post('/api/verify-security-answer', authLimiter, async (req, res) => {
    try {
        const { username, answerHash } = req.body;
        const user = await db.collection('profiles').findOne(
            { username: normalizeUsername(username) },
            { projection: { securityAnswerHash: 1, securityQuestion: 1 } }
        );
        if (!user || !user.securityAnswerHash)
            return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        const ok = answerHash === user.securityAnswerHash;
        if (ok) req.session.pwResetUser = normalizeUsername(username);
        res.json({ ok, question: user.securityQuestion || '' });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

app.post('/api/reset-password-anon', authLimiter, async (req, res) => {
    try {
        if (!req.session.pwResetUser)
            return res.status(403).json({ error: 'Güvenlik doğrulaması yapılmamış' });
        const { newPassword } = req.body;
        const pwErr = validatePassword(newPassword);
        if (pwErr) return res.status(400).json({ error: pwErr });

        const passwordHash = await bcrypt.hash(newPassword, 12);
        await db.collection('profiles').updateOne(
            { username: normalizeUsername(req.session.pwResetUser) },
            { $set: { passwordHash } }
        );
        delete req.session.pwResetUser;
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Şifre güncellenemedi' });
    }
});

/* ══════════════════════════════════════════════════
   ADMİN
══════════════════════════════════════════════════ */

app.post('/api/admin/ban', requireAdmin, async (req, res) => {
    try {
        const { uid, banned, banReason } = req.body;
        if (!uid) return res.status(400).json({ error: 'uid gerekli' });
        if (uid === req.session.uid) return res.status(400).json({ error: 'Kendi hesabınızı banlayamazsınız' });
        await db.collection('profiles').updateOne(
            { _id: uid },
            { $set: { banned: !!banned, banReason: banReason || '' } }
        );
        // Aktif session'larını sonlandır
        if (banned) {
            await db.collection('sessions').deleteMany({ 'session.uid': uid });
        }
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Ban işlemi başarısız' });
    }
});

app.post('/api/admin/delete', requireAdmin, async (req, res) => {
    try {
        const { uid } = req.body;
        if (!uid) return res.status(400).json({ error: 'uid gerekli' });
        if (uid === req.session.uid) return res.status(400).json({ error: 'Kendi hesabınızı silemezsiniz' });
        await db.collection('userdata').deleteOne({ _id: uid });
        await db.collection('profiles').deleteOne({ _id: uid });
        await db.collection('sessions').deleteMany({ 'session.uid': uid });
        _statsCache = null;
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Silme işlemi başarısız' });
    }
});

/* Admin: herhangi bir kullanıcının şifresini sıfırla */
app.post('/api/admin/reset-password', requireAdmin, async (req, res) => {
    try {
        const { uid, newPassword } = req.body;
        if (!uid) return res.status(400).json({ error: 'uid gerekli' });
        const pwErr = validatePassword(newPassword);
        if (pwErr) return res.status(400).json({ error: pwErr });
        const passwordHash = await bcrypt.hash(newPassword, 12);
        await db.collection('profiles').updateOne({ _id: uid }, { $set: { passwordHash } });
        await db.collection('sessions').deleteMany({ 'session.uid': uid });
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Şifre sıfırlanamadı' });
    }
});

/* ── Health check ── */
app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

/* ─── Start ─── */
connectDB().then(() => {
    app.listen(PORT, () => console.log(`[Kasaly API] Listening on port ${PORT} [${IS_PROD ? 'PRODUCTION' : 'DEV'}]`));
}).catch(err => {
    console.error('[MongoDB] Connection failed:', err);
    process.exit(1);
});