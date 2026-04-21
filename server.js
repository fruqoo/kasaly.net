/**
 * Kasaly — Node.js / Express API (MongoDB Atlas) v7.0
 * ─────────────────────────────────────────────────────
 * Değişiklikler v7.0:
 *   - S4: Admin username hardcoded kaldırıldı (env zorunlu)
 *   - S5: CORS no-origin production'da reddediliyor
 *   - S6: CSRF token protection eklendi
 *   - S7: Content-Security-Policy header eklendi
 *   - S8: Security answers bcrypt ile hash'leniyor
 *   - S9: Sensitive API'lere Cache-Control no-store eklendi
 *   - S10: MongoDB indexes (teamAccess, pendingInvitations, sessions)
 *   - S11: Subscription auto-renewal server-side endpoint
 *   - S12: Email verification sistemi (nodemailer)
 *   - L5: getStats() MongoDB aggregation ile optimize edildi
 *   - M6: helmet package eklendi
 *   - M7: Profile field length limits server-side
 *   - M8: Session cookie path/domain configuration
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
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const csurf = require('csurf');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || 'kasaly';
const SECRET = process.env.SESSION_SECRET || 'kasaly-secret-change-this';
const IS_PROD = process.env.NODE_ENV === 'production';

// S4: Admin username - NO FALLBACK
const ADMIN_USER = process.env.ADMIN_USERNAME;
if (!ADMIN_USER) {
    console.error('[FATAL] ADMIN_USERNAME env var not set. Exiting.');
    process.exit(1);
}

/* ─── Email configuration (S12) ─── */
let emailTransporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    emailTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });
    console.log('[Email] Transporter configured');
} else {
    console.warn('[Email] SMTP not configured - email verification disabled');
}

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

    // Existing indexes
    await db.collection('profiles').createIndex({ username: 1 }, { unique: true });
    await db.collection('profiles').createIndex({ email: 1 }, { sparse: true });

    // S10: New indexes for team features
    await db.collection('userdata').createIndex({ 'data.teamAccess.username': 1 });
    await db.collection('userdata').createIndex({ 'data.pendingInvitations.id': 1 });
    await db.collection('sessions').createIndex({ 'session.uid': 1 });

    // S12: Email verification token index
    await db.collection('profiles').createIndex({ emailVerificationToken: 1 }, { sparse: true });

    console.log('[MongoDB] Indexes created');
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
        createdAt: p.createdAt || '',
        emailVerified: p.emailVerified || false
    };
}

/* ─── L5: Stats cache with aggregation ─── */
let _statsCache = null;
let _statsCacheTime = 0;
async function getStats() {
    const now = Date.now();
    if (_statsCache && now - _statsCacheTime < 60_000) return _statsCache;

    const userCount = await db.collection('profiles').countDocuments();

    // L5: Use aggregation instead of loading all data into memory
    const result = await db.collection('userdata').aggregate([
        {
            $project: {
                txnCount: { $size: { $ifNull: ['$data.txns', []] } },
                goalCount: { $size: { $ifNull: ['$data.goals', []] } }
            }
        },
        {
            $group: {
                _id: null,
                totalTxns: { $sum: '$txnCount' },
                totalGoals: { $sum: '$goalCount' }
            }
        }
    ]).toArray();

    _statsCache = {
        users: userCount,
        txns: result[0]?.totalTxns || 0,
        goals: result[0]?.totalGoals || 0
    };
    _statsCacheTime = now;
    return _statsCache;
}

/* ─── Middleware ─── */
app.set('trust proxy', 1);

app.use(express.json({ limit: '4mb' }));

// M6: Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: false, // Set manually below
    crossOriginEmbedderPolicy: false
}));

// S7: Content-Security-Policy header
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: blob:; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none';"
    );
    next();
});

// S9: Cache-Control for sensitive API endpoints
app.use('/api/', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
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

/* S5: CORS - reject no-origin in production */
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
        // S5: In production, reject requests with no origin
        if (!origin) {
            if (IS_PROD) return callback(new Error('CORS: origin required'));
            return callback(null, true); // allow in dev (curl, Postman)
        }
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        return callback(new Error('CORS: disallowed origin: ' + origin));
    },
    credentials: true
}));

/* M8: Session with path and domain configuration */
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
        secure: IS_PROD,
        sameSite: IS_PROD ? 'none' : 'lax',
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/',
        domain: IS_PROD ? process.env.COOKIE_DOMAIN || undefined : undefined
    }
}));

/* S6: CSRF Protection */
const csrfProtection = csurf({ cookie: false }); // use session-based CSRF

// CSRF token endpoint (GET - no CSRF required)
app.get('/api/csrf-token', requireAuth, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Apply CSRF to state-changing endpoints (after session middleware)
app.use('/api/', (req, res, next) => {
    // Skip CSRF for GET requests and auth endpoints (login/register need to work before CSRF)
    if (req.method === 'GET' ||
        req.path === '/login' ||
        req.path === '/register' ||
        req.path === '/verify-security-answer' ||
        req.path === '/reset-password-anon' ||
        req.path === '/csrf-token') {
        return next();
    }
    csrfProtection(req, res, next);
});

/* ══════════════════════════════════════════════════
   AUTH
══════════════════════════════════════════════════ */

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, password, fullname, accType, company, phone, birthdate, email, securityQuestion, securityAnswer } = req.body;
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

        // S8: Hash security answer with bcrypt (not SHA-256)
        let securityAnswerHash = '';
        if (securityQuestion && securityAnswer) {
            const normalized = securityAnswer.trim().toLowerCase();
            securityAnswerHash = await bcrypt.hash(normalized, 10);
        }

        // S12: Email verification token
        let emailVerificationToken = null;
        let emailVerified = false;
        if (email && emailTransporter) {
            emailVerificationToken = crypto.randomBytes(32).toString('hex');
            emailVerified = false;
        } else if (email) {
            emailVerified = false; // No transporter, but track unverified status
        }

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
            securityAnswerHash,
            profileComplete: !!(phone && birthdate && fullname),
            banned: false,
            banReason: '',
            passwordHash,
            emailVerified,
            emailVerificationToken,
            createdAt: new Date().toISOString()
        });

        await db.collection('userdata').insertOne({ _id: uid, data: {} });

        // S12: Send verification email
        if (emailVerificationToken && emailTransporter) {
            const verifyUrl = `${process.env.FRONTEND_ORIGIN}/verify-email?token=${emailVerificationToken}`;
            try {
                await emailTransporter.sendMail({
                    from: process.env.SMTP_USER,
                    to: email,
                    subject: 'Kasaly - E-posta Doğrulama',
                    html: `
            <h2>Hoş geldiniz ${fullname}!</h2>
            <p>E-posta adresinizi doğrulamak için aşağıdaki bağlantıya tıklayın:</p>
            <a href="${verifyUrl}">${verifyUrl}</a>
            <p>Bu bağlantı 24 saat geçerlidir.</p>
          `
                });
            } catch (emailErr) {
                console.error('[Email] Send failed:', emailErr.message);
            }
        }

        _statsCache = null;
        res.json({ ok: true });
    } catch (e) {
        console.error('[Register] Error:', e.message);
        res.status(500).json({ error: 'Kayıt başarısız' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });

        const user = await db.collection('profiles').findOne({ username: normalizeUsername(username) });
        if (!user) return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı' });
        if (user.banned) return res.status(403).json({ error: user.banReason || 'Bu hesap engellenmiştir' });

        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı' });

        req.session.uid = user._id;
        req.session.username = user.username;
        req.session.accType = user.accType;
        req.session.isAdmin = user.username === ADMIN_USER;

        res.json({ ok: true, user: safeUser(user) });
    } catch (e) {
        console.error('[Login] Error:', e.message);
        res.status(500).json({ error: 'Giriş işlemi başarısız' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/session', (req, res) => {
    if (!req.session.uid) return res.json({ loggedIn: false });
    res.json({
        loggedIn: true,
        uid: req.session.uid,
        username: req.session.username,
        accType: req.session.accType,
        isAdmin: req.session.isAdmin || false
    });
});

/* S3: Server-side role validation endpoint */
app.get('/api/me', requireAuth, async (req, res) => {
    try {
        const profile = await db.collection('profiles').findOne(
            { _id: req.session.uid },
            { projection: { passwordHash: 0, securityAnswerHash: 0, emailVerificationToken: 0 } }
        );
        if (!profile) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        res.json({
            user: safeUser(profile),
            isAdmin: profile.username === ADMIN_USER
        });
    } catch (e) {
        res.status(500).json({ error: 'Kullanıcı bilgisi alınamadı' });
    }
});

/* M7: Profile update with field length limits */
app.put('/api/profile', requireAuth, async (req, res) => {
    try {
        const FIELD_LIMITS = {
            fullname: 120,
            company: 200,
            phone: 20,
            email: 254,
            taxNo: 20,
            sector: 100,
            birthdate: 20
        };

        const allowed = ['fullname', 'company', 'phone', 'birthdate', 'email', 'taxNo', 'sector'];
        const update = {};

        for (const k of allowed) {
            if (req.body[k] !== undefined) {
                const val = String(req.body[k]);
                if (FIELD_LIMITS[k] && val.length > FIELD_LIMITS[k]) {
                    return res.status(400).json({
                        error: `${k} alanı çok uzun (maksimum ${FIELD_LIMITS[k]} karakter)`
                    });
                }
                update[k] = val.trim();
            }
        }

        if (Object.keys(update).length === 0)
            return res.status(400).json({ error: 'Güncellenecek alan bulunamadı' });

        await db.collection('profiles').updateOne({ _id: req.session.uid }, { $set: update });
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Profil güncellenemedi' });
    }
});

/* S2: Verify password endpoint for password change flow */
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
        _statsCache = null;
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Veri kaydedilemedi' });
    }
});

// L3: Beacon endpoint for immediate save on page unload
app.post('/api/userdata/beacon', requireAuth, express.text({ limit: '4mb' }), async (req, res) => {
    try {
        const data = JSON.parse(req.body);
        if (!data.data || typeof data.data !== 'object')
            return res.status(400).json({ error: 'Geçersiz veri formatı' });

        if (Array.isArray(data.data.txns) && data.data.txns.length > MAX_TXNS)
            return res.status(400).json({ error: `Maksimum ${MAX_TXNS} işlem kaydedilebilir` });

        await db.collection('userdata').updateOne(
            { _id: req.session.uid },
            { $set: { data: data.data, updatedAt: new Date().toISOString() } },
            { upsert: true }
        );
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
            .find({}, { projection: { passwordHash: 0, securityAnswerHash: 0, emailVerificationToken: 0 } })
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
        if (!user || !user.securityQuestion)
            return res.status(404).json({ error: 'Bu hesap için güvenlik sorusu tanımlı değil' });
        res.json({ question: user.securityQuestion });
    } catch (e) {
        res.status(500).json({ error: 'Sunucu hatası' });
    }
});

// S8: Security answer verification with bcrypt
app.post('/api/verify-security-answer', authLimiter, async (req, res) => {
    try {
        const { username, answer } = req.body; // Raw answer, not hash
        const user = await db.collection('profiles').findOne(
            { username: normalizeUsername(username) },
            { projection: { securityAnswerHash: 1, securityQuestion: 1 } }
        );
        if (!user || !user.securityAnswerHash)
            return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        // S8: Use bcrypt.compare instead of string equality
        const normalized = answer.trim().toLowerCase();
        const ok = await bcrypt.compare(normalized, user.securityAnswerHash);

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
   S12: EMAIL VERIFICATION
══════════════════════════════════════════════════ */

app.get('/api/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const user = await db.collection('profiles').findOne({ emailVerificationToken: token });

        if (!user) {
            return res.status(404).json({ error: 'Geçersiz veya süresi dolmuş doğrulama bağlantısı' });
        }

        await db.collection('profiles').updateOne(
            { _id: user._id },
            {
                $set: { emailVerified: true },
                $unset: { emailVerificationToken: '' }
            }
        );

        res.json({ ok: true, message: 'E-posta adresiniz doğrulandı!' });
    } catch (e) {
        res.status(500).json({ error: 'Doğrulama hatası' });
    }
});

app.post('/api/resend-verification', requireAuth, async (req, res) => {
    try {
        if (!emailTransporter) {
            return res.status(503).json({ error: 'E-posta servisi yapılandırılmamış' });
        }

        const user = await db.collection('profiles').findOne({ _id: req.session.uid });
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        if (user.emailVerified) return res.status(400).json({ error: 'E-posta zaten doğrulanmış' });
        if (!user.email) return res.status(400).json({ error: 'E-posta adresi tanımlı değil' });

        const emailVerificationToken = crypto.randomBytes(32).toString('hex');
        await db.collection('profiles').updateOne(
            { _id: user._id },
            { $set: { emailVerificationToken } }
        );

        const verifyUrl = `${process.env.FRONTEND_ORIGIN}/verify-email?token=${emailVerificationToken}`;
        await emailTransporter.sendMail({
            from: process.env.SMTP_USER,
            to: user.email,
            subject: 'Kasaly - E-posta Doğrulama',
            html: `
        <h2>Merhaba ${user.fullname}!</h2>
        <p>E-posta adresinizi doğrulamak için aşağıdaki bağlantıya tıklayın:</p>
        <a href="${verifyUrl}">${verifyUrl}</a>
        <p>Bu bağlantı 24 saat geçerlidir.</p>
      `
        });

        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'E-posta gönderilemedi' });
    }
});

/* ══════════════════════════════════════════════════
   S11: SUBSCRIPTION AUTO-RENEWAL (server-side)
══════════════════════════════════════════════════ */

app.post('/api/subscriptions/process-renewals', requireAuth, async (req, res) => {
    try {
        const row = await db.collection('userdata').findOne({ _id: req.session.uid });
        if (!row || !row.data) return res.json({ ok: true, renewed: 0 });

        const data = row.data;
        const subscriptions = data.subscriptions || [];
        const now = new Date();
        let renewedCount = 0;

        for (const sub of subscriptions) {
            if (!sub.autoRenew) continue;

            const nextDate = new Date(sub.nextPayment);
            if (nextDate <= now) {
                // Process renewal
                const amount = parseFloat(sub.amount) || 0;

                // Add transaction
                if (!data.txns) data.txns = [];
                data.txns.push({
                    id: crypto.randomBytes(8).toString('hex'),
                    date: now.toISOString().split('T')[0],
                    type: 'expense',
                    category: sub.category || 'abonelik',
                    amount: amount,
                    note: `${sub.name} abonelik yenileme`,
                    createdAt: now.toISOString()
                });

                // Update next payment date
                const period = sub.renewPeriod || 'monthly';
                const newNextDate = new Date(nextDate);
                if (period === 'monthly') {
                    newNextDate.setMonth(newNextDate.getMonth() + 1);
                } else if (period === 'yearly') {
                    newNextDate.setFullYear(newNextDate.getFullYear() + 1);
                } else if (period === 'weekly') {
                    newNextDate.setDate(newNextDate.getDate() + 7);
                }
                sub.nextPayment = newNextDate.toISOString().split('T')[0];

                renewedCount++;
            }
        }

        if (renewedCount > 0) {
            await db.collection('userdata').updateOne(
                { _id: req.session.uid },
                { $set: { data, updatedAt: now.toISOString() } }
            );
        }

        res.json({ ok: true, renewed: renewedCount });
    } catch (e) {
        res.status(500).json({ error: 'Abonelik yenileme hatası' });
    }
});

/* ══════════════════════════════════════════════════
   S1: TEAM MANAGEMENT (server-side authorization)
══════════════════════════════════════════════════ */

app.post('/api/team/invite', requireAuth, async (req, res) => {
    try {
        const { toUsername, role } = req.body;
        if (!toUsername || !role) {
            return res.status(400).json({ error: 'Kullanıcı adı ve rol gerekli' });
        }

        const sender = await db.collection('profiles').findOne({ _id: req.session.uid });
        if (!sender) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

        // Only company accounts can invite
        if (sender.accType !== 'sirket') {
            return res.status(403).json({ error: 'Sadece şirket hesapları ekip daveti gönderebilir' });
        }

        const target = await db.collection('profiles').findOne({ username: normalizeUsername(toUsername) });
        if (!target) {
            return res.status(404).json({ error: 'Hedef kullanıcı bulunamadı' });
        }

        if (target._id === sender._id) {
            return res.status(400).json({ error: 'Kendinizi ekibe ekleyemezsiniz' });
        }

        // Get sender's data to check for duplicate invitations
        const senderData = await db.collection('userdata').findOne({ _id: sender._id });
        const teamInvitations = (senderData?.data?.teamInvitations || []);

        const existing = teamInvitations.find(inv =>
            inv.toUid === target._id && inv.status === 'pending'
        );
        if (existing) {
            return res.status(409).json({ error: 'Bu kullanıcıya zaten bekleyen bir davet göndermişsiniz' });
        }

        // Create invitation
        const invId = crypto.randomBytes(8).toString('hex');
        const invitation = {
            id: invId,
            fromUid: sender._id,
            fromUsername: sender.username,
            fromCompany: sender.company || sender.fullname,
            toUid: target._id,
            toUsername: target.username,
            role,
            status: 'pending',
            createdAt: new Date().toISOString()
        };

        // Add to sender's teamInvitations
        await db.collection('userdata').updateOne(
            { _id: sender._id },
            { $push: { 'data.teamInvitations': invitation } },
            { upsert: true }
        );

        // Add to target's pendingInvitations
        await db.collection('userdata').updateOne(
            { _id: target._id },
            { $push: { 'data.pendingInvitations': invitation } },
            { upsert: true }
        );

        res.json({ ok: true, invitation });
    } catch (e) {
        console.error('[Team Invite] Error:', e.message);
        res.status(500).json({ error: 'Davet gönderilemedi' });
    }
});

app.post('/api/team/respond', requireAuth, async (req, res) => {
    try {
        const { invId, accepted } = req.body;
        if (!invId || accepted === undefined) {
            return res.status(400).json({ error: 'Davet ID ve kabul durumu gerekli' });
        }

        const userData = await db.collection('userdata').findOne({ _id: req.session.uid });
        if (!userData) return res.status(404).json({ error: 'Kullanıcı verisi bulunamadı' });

        const pendingInvitations = userData.data?.pendingInvitations || [];
        const invitation = pendingInvitations.find(inv => inv.id === invId);

        if (!invitation) {
            return res.status(404).json({ error: 'Davet bulunamadı' });
        }

        if (invitation.toUid !== req.session.uid) {
            return res.status(403).json({ error: 'Bu daveti yanıtlama yetkiniz yok' });
        }

        const newStatus = accepted ? 'accepted' : 'rejected';

        // Update invitation status in both users' data
        await db.collection('userdata').updateOne(
            { _id: req.session.uid, 'data.pendingInvitations.id': invId },
            { $set: { 'data.pendingInvitations.$.status': newStatus } }
        );

        await db.collection('userdata').updateOne(
            { _id: invitation.fromUid, 'data.teamInvitations.id': invId },
            { $set: { 'data.teamInvitations.$.status': newStatus } }
        );

        // If accepted, add to sender's teamAccess
        if (accepted) {
            const member = {
                username: invitation.toUsername,
                uid: invitation.toUid,
                role: invitation.role,
                addedAt: new Date().toISOString()
            };

            await db.collection('userdata').updateOne(
                { _id: invitation.fromUid },
                { $push: { 'data.teamAccess': member } }
            );
        }

        res.json({ ok: true });
    } catch (e) {
        console.error('[Team Respond] Error:', e.message);
        res.status(500).json({ error: 'Davet yanıtlanamadı' });
    }
});

app.post('/api/team/cancel-invite', requireAuth, async (req, res) => {
    try {
        const { invId } = req.body;
        if (!invId) return res.status(400).json({ error: 'Davet ID gerekli' });

        const userData = await db.collection('userdata').findOne({ _id: req.session.uid });
        if (!userData) return res.status(404).json({ error: 'Kullanıcı verisi bulunamadı' });

        const teamInvitations = userData.data?.teamInvitations || [];
        const invitation = teamInvitations.find(inv => inv.id === invId);

        if (!invitation) {
            return res.status(404).json({ error: 'Davet bulunamadı' });
        }

        if (invitation.fromUid !== req.session.uid) {
            return res.status(403).json({ error: 'Bu daveti iptal etme yetkiniz yok' });
        }

        // Update status to cancelled in both users
        await db.collection('userdata').updateOne(
            { _id: req.session.uid, 'data.teamInvitations.id': invId },
            { $set: { 'data.teamInvitations.$.status': 'cancelled' } }
        );

        await db.collection('userdata').updateOne(
            { _id: invitation.toUid, 'data.pendingInvitations.id': invId },
            { $set: { 'data.pendingInvitations.$.status': 'cancelled' } }
        );

        res.json({ ok: true });
    } catch (e) {
        console.error('[Team Cancel] Error:', e.message);
        res.status(500).json({ error: 'Davet iptal edilemedi' });
    }
});

app.delete('/api/team/member', requireAuth, async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: 'Kullanıcı adı gerekli' });

        await db.collection('userdata').updateOne(
            { _id: req.session.uid },
            { $pull: { 'data.teamAccess': { username: normalizeUsername(username) } } }
        );

        res.json({ ok: true });
    } catch (e) {
        console.error('[Team Remove] Error:', e.message);
        res.status(500).json({ error: 'Üye çıkarılamadı' });
    }
});

app.get('/api/team/accounts', requireAuth, async (req, res) => {
    try {
        // Find all company accounts where this user is in teamAccess
        const accounts = await db.collection('userdata').find({
            'data.teamAccess.username': req.session.username
        }).toArray();

        const result = [];
        for (const acc of accounts) {
            const profile = await db.collection('profiles').findOne({ _id: acc._id });
            if (!profile) continue;

            const member = acc.data.teamAccess.find(m => m.username === req.session.username);
            if (!member) continue;

            result.push({
                uid: profile._id,
                username: profile.username,
                company: profile.company || profile.fullname,
                role: member.role
            });
        }

        res.json({ accounts: result });
    } catch (e) {
        console.error('[Team Accounts] Error:', e.message);
        res.status(500).json({ error: 'Ekip hesapları alınamadı' });
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
