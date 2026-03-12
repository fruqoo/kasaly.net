'use strict';

// ══════════════════════════════════════════════════════════
//  SECURITY UTILITIES
// ══════════════════════════════════════════════════════════
/** Escape user-supplied strings before insertion into innerHTML to prevent XSS. */
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Generate a cryptographically-random session token. */
function cryptoToken() {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

/** Debounce: delay fn execution until after `wait` ms of silence. */
function debounce(fn, wait) {
  let t;
  return function (...args) { clearTimeout(t); t = setTimeout(() => fn.apply(this, args), wait); };
}

/** Validates password complexity: min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char. */
function validatePassword(pw) {
  if (!pw || pw.length < 8) return { ok: false, msg: 'En az 8 karakter uzunluğunda olmalıdır' };
  if (!/[A-Z]/.test(pw)) return { ok: false, msg: 'En az 1 büyük harf içermelidir' };
  if (!/[a-z]/.test(pw)) return { ok: false, msg: 'En az 1 küçük harf içermelidir' };
  if (!/[0-9]/.test(pw)) return { ok: false, msg: 'En az 1 rakam içermelidir' };
  if (!/[^A-Za-z0-9]/.test(pw)) return { ok: false, msg: 'En az 1 özel karakter (!,@,#,vs.) içermelidir' };
  return { ok: true, msg: 'Geçerli' };
}

/** Validates personal data strict rules. */
function validatePersonalData(data) {
  const { fullname, email, phone, birthdate } = data;
  if (!fullname || fullname.trim().split(/\s+/).length < 2) return { ok: false, msg: 'Ad ve Soyad (en az 2 kelime) zorunludur' };
  if (fullname.trim().length < 5) return { ok: false, msg: 'Ad ve Soyad çok kısa' };
  if (!/^[A-Za-zÇçĞğİıÖöŞşÜü\s]+$/.test(fullname)) return { ok: false, msg: 'Ad ve Soyad sadece harflerden oluşmalıdır' };

  if (!email || !/@/.test(email) || !/\./.test(email)) return { ok: false, msg: 'Geçerli bir e-posta adresi giriniz' };

  if (!phone || !/^0[0-9]{10}$/.test(phone)) return { ok: false, msg: 'Telefon numarası 0 ile başlamalı ve tam 11 haneli olmalıdır (Sadece rakam)' };

  if (!birthdate) return { ok: false, msg: 'Doğum tarihi zorunludur' };
  const bd = new Date(birthdate);
  const age = (new Date() - bd) / (1000 * 60 * 60 * 24 * 365.25);
  if (age < 13) return { ok: false, msg: 'Kayıt olmak için en az 13 yaşında olmalısınız' };
  if (age > 100) return { ok: false, msg: 'Doğum tarihi geçersiz (>100 yaş)' };

  return { ok: true, msg: 'Geçerli' };
}

/** Hashes a security answer. */
async function hashAnswer(str) {
  const normalized = str.trim().toLowerCase();
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(normalized));
  return 'sha256:' + Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
// ══════════════════════════════════════════════════════════
//  AUTH SLIDES
// ══════════════════════════════════════════════════════════
const SLIDES = [
  { q: 'Finansal özgürlük,<br>her adımı takip etmekten geçer.', s: 'Kasaly ile paranızın kontrolü sizde.' },
  { q: 'İyi bir muhasebe,<br>başarılı bir işletmenin temelidir.', s: 'Gelir ve giderlerinizi kolayca yönetin.' },
  { q: 'Her harcama bir karar,<br>her tasarruf bir yatırımdır.', s: 'Hedeflerinize adım adım ulaşın.' },
];
let slideIdx = 0;
function initSlides() {
  const dots = document.getElementById('auth-slide-dots');
  dots.innerHTML = SLIDES.map((_, i) => `<div class="auth-sdot${i === 0 ? ' on' : ''}" onclick="goSlide(${i})"></div>`).join('');
  goSlide(0);
  _slideInterval = setInterval(() => goSlide((slideIdx + 1) % SLIDES.length), 5000);
}
function goSlide(i) {
  slideIdx = i;
  const q = document.getElementById('auth-quote'), s = document.getElementById('auth-qsub');
  q.classList.remove('in'); s.classList.remove('in');
  setTimeout(() => { q.innerHTML = SLIDES[i].q; s.textContent = SLIDES[i].s; q.classList.add('in'); s.classList.add('in'); }, 200);
  document.querySelectorAll('.auth-sdot').forEach((d, j) => d.classList.toggle('on', j === i));
}

// Auth pane navigation - animasyonlu geçiş
let curPane = 0;
const PANE_IDS = ['pane-login', 'pane-register', 'pane-forgot', 'pane-account-picker'];

function goAuthPane(idx, force) {
  if (idx === curPane && !force) return;
  const oldPane = document.getElementById(PANE_IDS[curPane]);
  const newPane = document.getElementById(PANE_IDS[idx]);
  // Sıfırla — tüm panelleri gizle
  PANE_IDS.forEach(id => {
    const p = document.getElementById(id);
    p.classList.remove('auth-pane-active');
    p.style.transform = '';
    p.style.opacity = '';
    p.style.pointerEvents = '';
  });
  if (force || idx === curPane) {
    // Animasyonsuz direkt göster
    newPane.classList.add('auth-pane-active');
    curPane = idx;
    clearAuthMsgs();
    return;
  }
  // Yönü belirle
  const dir = idx > curPane ? 1 : -1;
  newPane.style.transform = 'translateX(' + (dir * 32) + 'px)';
  newPane.style.opacity = '0';
  newPane.style.pointerEvents = 'none';
  void newPane.offsetWidth;
  oldPane.style.transform = 'translateX(' + (-dir * 32) + 'px)';
  oldPane.style.opacity = '0';
  oldPane.style.pointerEvents = 'none';
  newPane.style.transform = 'translateX(0)';
  newPane.style.opacity = '1';
  newPane.style.pointerEvents = 'auto';
  setTimeout(() => {
    oldPane.style.transform = '';
    oldPane.style.opacity = '';
    oldPane.style.pointerEvents = '';
    newPane.classList.add('auth-pane-active');
    newPane.style.transform = '';
    newPane.style.opacity = '';
    newPane.style.pointerEvents = '';
  }, 380);
  curPane = idx;
  clearAuthMsgs();
}
function clearAuthMsgs() { ['li-msg', 'reg-msg', 'fp-msg'].forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; }); }
function showMsg(id, msg, type = 'err') { const el = document.getElementById(id); el.textContent = msg; el.className = 'amsg ' + (type === 'ok' ? 'ok' : 'err'); el.style.display = 'block'; }

// ══════════════════════════════════════════════════════════
//  REGISTER STEPS
// ══════════════════════════════════════════════════════════
let regAcct = 'bireysel', regStep = 1;
function selAcct(t) {
  regAcct = t;
  document.getElementById('atype-bireysel').classList.toggle('on', t === 'bireysel');
  document.getElementById('atype-sirket').classList.toggle('on', t === 'sirket');
}
function rsGo(step) {
  if (step === 3) {
    const fname = document.getElementById('r-fname').value.trim();
    const lname = document.getElementById('r-lname').value.trim();
    const phone = document.getElementById('r-phone').value.trim();
    if (!fname || !lname) { showMsg('reg-msg', 'Ad ve soyad alanları zorunludur'); return; }
    if (!phone) { showMsg('reg-msg', 'Telefon numarası zorunludur'); return; }
    if (regAcct === 'sirket' && !document.getElementById('r-company').value.trim()) { showMsg('reg-msg', 'Şirket adı zorunludur'); return; }
    if (regAcct === 'bireysel') {
      const occ = document.getElementById('r-occupation').value;
      if (!occ) { showMsg('reg-msg', 'Lütfen meslek/uğraş alanınızı seçin'); return; }
    }
  }
  regStep = step;
  [1, 2, 3].forEach(s => {
    const el = document.getElementById('rstep-' + s);
    if (el) el.style.display = s === step ? 'block' : 'none';
  });
  // Update step indicator
  [1, 2, 3].forEach(s => {
    const dot = document.getElementById('rs-' + s);
    const line = document.getElementById('rsl-' + s);
    if (!dot) return;
    if (s < step) { dot.className = 'astep done'; }
    else if (s === step) { dot.className = 'astep on'; }
    else { dot.className = 'astep'; }
    if (line) line.className = 'astep-line' + (s < step ? ' on' : '');
  });
  // Show company fields in step 2
  if (step === 2) {
    document.getElementById('rf-company').style.display = regAcct === 'sirket' ? 'block' : 'none';
    document.getElementById('rf-personal-title').textContent = regAcct === 'sirket' ? 'Yetkili Kişi Bilgileri' : 'Kişisel Bilgiler';
    const bireyselOnly = document.getElementById('rf-bireysel-only');
    if (bireyselOnly) bireyselOnly.style.display = regAcct === 'sirket' ? 'none' : 'block';
  }
}

// ══════════════════════════════════════════════════════════
//  PW STRENGTH
// ══════════════════════════════════════════════════════════
function pwStrength(pw) { let s = 0; if (pw.length >= 6) s++; if (pw.length >= 10) s++; if (/[A-Z]/.test(pw)) s++; if (/[0-9]/.test(pw)) s++; if (/[^a-zA-Z0-9]/.test(pw)) s++; return s; }
function renderPwBar(inputId, fillId, hintId) {
  const pw = document.getElementById(inputId).value;
  const s = pwStrength(pw);
  const pct = [0, 20, 40, 62, 82, 100][s];
  const col = s <= 1 ? '#ef4444' : s <= 2 ? '#f59e0b' : s <= 3 ? '#3b82f6' : '#22c55e';
  const lbls = ['', 'Çok zayıf', 'Zayıf', 'Orta', 'Güçlü', 'Çok güçlü'];
  document.getElementById(fillId).style.width = pct + '%';
  document.getElementById(fillId).style.background = col;
  if (hintId) document.getElementById(hintId).textContent = pw.length > 0 ? lbls[s] : '';
}
function togglePw(id, btn) { const i = document.getElementById(id); const s = i.type === 'password'; i.type = s ? 'text' : 'password'; btn.textContent = s ? '🙈' : '👁'; }
/**
 * Hash a password with SHA-256 via Web Crypto API.
 * Returns a hex string prefixed with 'sha256:' to distinguish from old hashes.
 * Falls back to the legacy djb2 hash if called synchronously (for legacy migration).
 */
async function hashPwAsync(pw) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(pw));
  const hex = Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
  return 'sha256:' + hex;
}
/** Legacy hash — artık kullanılmıyor (MongoDB bcrypt kullanıyor) */
function hashPwLegacy(pw) { return ''; }

// ══════════════════════════════════════════════════════════
//  USER STORE
// ══════════════════════════════════════════════════════════
function getUsers() { try { return JSON.parse(KasaDB.getItem('kt_users') || '[]'); } catch { return []; } }
function saveUsers(u) { KasaDB.setItem('kt_users', JSON.stringify(u)); }
function getUserData(uid) { try { return JSON.parse(KasaDB.getItem('kt_d_' + uid) || 'null'); } catch { return null; } }
function saveUserData(uid, d) { KasaDB.setItem('kt_d_' + uid, JSON.stringify(d)); }

let SESSION = null;
// Session watcher — stored so it can be cleared on logout
let _sessionWatcherId = null;
function _startSessionWatcher() {
  if (_sessionWatcherId) return;
  _sessionWatcherId = setInterval(() => {
    if (!SESSION || !SESSION.sessionId) return;
    try {
      const dStr = KasaDB.getItem('kt_d_' + SESSION.uid);
      if (!dStr) return;
      const dObj = JSON.parse(dStr);
      if (dObj && dObj.deviceSessions) {
        const ds = dObj.deviceSessions.find(s => s.sessionId === SESSION.sessionId);
        if (ds && ds.isActive === false) {
          clearInterval(_sessionWatcherId);
          _sessionWatcherId = null;
          doLogout(true).then(() => window.location.reload());
        }
      }
    } catch (e) { }
  }, 5000);
}

function loadSession() {
  // MongoDB session cookie tabanlı — sadece sessionStorage'dan yükle
  const s = sessionStorage.getItem('kt_sess');
  if (s) {
    try {
      SESSION = JSON.parse(s);
      return true;
    } catch { }
  }
  return false;
}
function mkSess(u) { return { uid: u.uid, username: u.username, fullname: u.fullname, accType: u.accType, company: u.company || '', sector: u.sector || '', taxNo: u.taxNo || '', avatar: u.avatar || null, phone: u.phone || '', birthdate: u.birthdate || '', email: u.email || '', profileComplete: u.profileComplete || false }; }
function persistSession(u, remember) {
  SESSION = mkSess(u);
  sessionStorage.setItem('kt_sess', JSON.stringify(SESSION));
  // "Beni hatırla" — MongoDB session cookie zaten 30 gün geçerli
  // Ek token gerekmez
}

// ══════════════════════════════════════════════════════════
//  PER-USER DATA
// ══════════════════════════════════════════════════════════
const DEFAULT_S = { reminder: true, debtAlert: true, confirmDelete: true, currency: '₺', accentColor: '#22c55e', accentDim: 'rgba(34,197,94,.13)', sidebarWidth: 264, authPhoto: '', lightTheme: false, onboarded: false };
let _D = null;
function D() {
  if (!_D) {
    const d = getUserData(SESSION.uid);
    if (d) {
      if (!d.settings) d.settings = {};
      for (const k in DEFAULT_S) if (d.settings[k] === undefined) d.settings[k] = DEFAULT_S[k];
      _D = d;
    } else {
      _D = { txns: [], debts: [], goals: [], invoices: [], employees: [], logs: [], settings: { ...DEFAULT_S } };
    }
  }
  return _D;
}
// Debounced saveD — 400ms içinde birden fazla çağrı gelirse sadece son çağrı network'e gider
let _saveDTimer = null;
function saveD() {
  if (!_D) return;
  // Belleği hemen güncelle (senkron)
  saveUserData(SESSION.uid, _D);
}

function applyTheme() {
  if (D().settings.lightTheme) document.body.setAttribute('data-theme', 'light');
  else document.body.removeAttribute('data-theme');
}

// Onboarding accent color selection
let _obAccentColor = '#22c55e', _obAccentDim = 'rgba(34,197,94,.13)';
function selectObAccent(el) {
  document.querySelectorAll('#ob-swatches .swatch').forEach(s => s.classList.remove('on'));
  el.classList.add('on');
  _obAccentColor = el.dataset.color;
  _obAccentDim = el.dataset.dim;
  document.documentElement.style.setProperty('--green', _obAccentColor);
  document.documentElement.style.setProperty('--green-dim', _obAccentDim);
}

function finishOnboarding() {
  const s = D().settings;
  s.onboarded = true;
  s.currency = document.getElementById('ob-currency').value;
  s.reminder = document.getElementById('ob-reminder').value === 'true';
  s.accentColor = _obAccentColor;
  s.accentDim = _obAccentDim;
  const themeEl = document.getElementById('ob-theme');
  if (themeEl) s.lightTheme = themeEl.value === 'light';
  saveD();
  applyTheme();
  document.documentElement.style.setProperty('--green', s.accentColor);
  document.documentElement.style.setProperty('--green-dim', s.accentDim);
  document.getElementById('onboarding-modal').classList.remove('open');
  document.querySelectorAll('.cur-sym').forEach(el => el.textContent = s.currency || '₺');
  toast('Tercihleriniz kaydedildi. Sisteme hoş geldiniz! 🎉', 'ok');
  // Launch tutorial after onboarding
  setTimeout(() => startTutorial(), 500);
}

let _idleTimeout = null;
let _idleAbortCtrl = null;
function _stopIdleTimer() {
  clearTimeout(_idleTimeout);
  if (_idleAbortCtrl) { _idleAbortCtrl.abort(); _idleAbortCtrl = null; }
}
function resetIdleTimer() {
  clearTimeout(_idleTimeout);
  if (!SESSION) return;
  _idleTimeout = setTimeout(() => {
    showConfirm('Güvenlik nedeniyle oturumunuz zaman aşımına uğradı (5 dakika). Lütfen tekrar giriş yapın.', {
      title: '⏳ Oturum Zaman Aşımı',
      confirmText: 'Çıkış Yap',
      cancelText: 'Devam Et',
      danger: false
    }).then(ok => { if (ok) doLogout(true); else resetIdleTimer(); });
  }, 5 * 60 * 1000);
}
function _startIdleTimer() {
  _stopIdleTimer();
  _idleAbortCtrl = new AbortController();
  const opts = { signal: _idleAbortCtrl.signal, passive: true };
  // Throttle mousemove/scroll to fire at most once per second
  let _lastActivity = 0;
  function onActivity() {
    const now = Date.now();
    if (now - _lastActivity < 1000) return;
    _lastActivity = now;
    resetIdleTimer();
  }
  document.addEventListener('mousemove', onActivity, opts);
  document.addEventListener('keydown', resetIdleTimer, opts);
  document.addEventListener('click', resetIdleTimer, opts);
  document.addEventListener('touchstart', resetIdleTimer, opts);
  document.addEventListener('scroll', onActivity, opts);
  resetIdleTimer();
}

// ══════════════════════════════════════════════════════════
//  LOG
// ══════════════════════════════════════════════════════════
function addLog(type, cat, msg, detail = '') {
  const d = D();
  d.logs.push({ id: Date.now() + Math.random(), type, cat, msg, detail, ts: new Date().toISOString() });
  // Performans: max 500 log sakla, eskiler otomatik kırpılır
  if (d.logs.length > 500) d.logs = d.logs.slice(-500);
}

function renderLog() {
  const tf = document.getElementById('log-type-f').value, cf = document.getElementById('log-cat-f').value;
  let data = [...D().logs].reverse().slice(0, 300); // Performans: max 300 log
  if (tf) data = data.filter(l => l.type === tf);
  if (cf) data = data.filter(l => l.cat === cf);
  const list = document.getElementById('log-list'), empty = document.getElementById('log-empty');
  if (!data.length) { list.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  const tl = { add: '➕ Eklendi', edit: '✏️ Düzenlendi', delete: '🗑 Silindi', pay: '💳 Ödeme', system: '🔧 Sistem' };
  const cl = { txn: 'İşlem', debt: 'Borç', goal: 'Hedef', invoice: 'Fatura', employee: 'Çalışan', auth: 'Oturum' };
  list.innerHTML = data.map(l => {
    const d2 = new Date(l.ts);
    return `<div class="log-item"><div class="log-dot ${l.type}" style="margin-top:5px"></div><div class="log-content"><div class="log-msg">
      <span class="badge badge-gray" style="margin-right:5px;font-size:10px">${escHtml(cl[l.cat] || l.cat)}</span>
      <span class="badge ${l.type === 'delete' ? 'badge-red' : l.type === 'add' ? 'badge-green' : l.type === 'edit' ? 'badge-blue' : l.type === 'pay' ? 'badge-yellow' : 'badge-purple'}" style="margin-right:8px;font-size:10px">${escHtml(tl[l.type] || l.type)}</span>
      ${escHtml(l.msg)}${l.detail ? `<span style="color:var(--text-muted)"> — ${escHtml(l.detail)}</span>` : ''}
    </div><div class="log-time">${escHtml(d2.toLocaleDateString('tr-TR', { day: '2-digit', month: 'long', year: 'numeric' }))} saat ${escHtml(d2.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }))}</div></div></div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════
//  UTILS
// ══════════════════════════════════════════════════════════
function cur() { return D().settings.currency || '₺'; }
function fmt(n) { return cur() + Number(n || 0).toLocaleString('tr-TR', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
function today() { return new Date().toISOString().split('T')[0]; }
function uid() {
  // Cryptographically-seeded collision-resistant ID (timestamp + 32-bit random)
  const arr = new Uint32Array(1);
  if (typeof crypto !== 'undefined') crypto.getRandomValues(arr);
  else arr[0] = Math.floor(Math.random() * 4294967295);
  return Date.now() * 1000 + (arr[0] % 1000);
}
// NOTE: cur() is defined once above. The duplicate definition was removed (bugfix).
function bal() { return D().txns.reduce((a, t) => t.type === 'income' ? a + t.amount : a - t.amount, 0); }
function isSirket() { return SESSION && SESSION.accType === 'sirket'; }
/**
 * showConfirm — Custom in-app confirmation modal.
 * Returns a Promise<boolean>.
 * @param {string} msg        - Main message text
 * @param {object} [opts]     - { title, confirmText, cancelText, danger }
 */
function showConfirm(msg, opts = {}) {
  return new Promise(resolve => {
    const overlay = document.getElementById('confirm-modal');
    // İstenen ikon veya varsayılanlara göre seç
    const iconEl = document.getElementById('confirm-modal-icon');
    if (iconEl) {
      iconEl.textContent = opts.icon || (opts.danger === false ? 'ℹ️' : '⚠️');
    }
    document.getElementById('confirm-modal-title').textContent = opts.title || 'Onay';
    document.getElementById('confirm-modal-msg').textContent = msg;
    const okBtn = document.getElementById('confirm-modal-ok');
    const cancelBtn = document.getElementById('confirm-modal-cancel');
    okBtn.textContent = opts.confirmText || 'Evet, Devam Et';
    cancelBtn.textContent = opts.cancelText || 'İptal';
    okBtn.className = 'btn ' + (opts.danger !== false ? 'btn-red' : 'btn-green');
    overlay.classList.add('open');
    function cleanup(result) {
      overlay.classList.remove('open');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      overlay.removeEventListener('click', onBackdrop);
      document.removeEventListener('keydown', onKey);
      resolve(result);
    }
    function onOk() { cleanup(true); }
    function onCancel() { cleanup(false); }
    function onBackdrop(e) { if (e.target === overlay) cleanup(false); }
    function onKey(e) { if (e.key === 'Escape') cleanup(false); if (e.key === 'Enter') cleanup(true); }
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    overlay.addEventListener('click', onBackdrop);
    document.addEventListener('keydown', onKey);
    // Butona focus ver
    setTimeout(() => cancelBtn.focus(), 80);
  });
}

/** confirmD — silme onayı gerekiyorsa showConfirm, yoksa doğrudan true döner (Promise). */
async function confirmD(msg) { return !D().settings.confirmDelete || showConfirm(msg, { danger: true }); }
function toast(msg, type = 'success') {
  const el = document.getElementById('toast'); document.getElementById('toast-msg').textContent = msg;
  el.className = 'toast ' + type + ' show'; clearTimeout(el._t); el._t = setTimeout(() => el.classList.remove('show'), 3200);
}

// ══════════════════════════════════════════════════════════
//  AUTH ACTIONS
// ══════════════════════════════════════════════════════════
let _pendingUser = null, _pendingRem = false, _pendingAccounts = [];

function getTeamAccountsFor(username) {
  const accounts = [];
  for (const u of getUsers()) {
    if (u.accType !== 'sirket') continue;
    const d = getUserData(u.uid);
    if (!d || !d.teamAccess) continue;
    const entry = d.teamAccess.find(tm => tm.username.toLowerCase() === username.toLowerCase());
    if (entry) accounts.push({ uid: u.uid, username: u.username, fullname: u.fullname, accType: u.accType, company: u.company || u.fullname, sector: u.sector || '', taxNo: u.taxNo || '', role: entry.role, isOwner: false });
  }
  return accounts;
}

async function doLogin() {
  const user = document.getElementById('li-user').value.trim();
  const pass = document.getElementById('li-pass').value;
  const rem = document.getElementById('li-remember').checked;
  if (!user || !pass) { showMsg('li-msg', 'Kullanıcı adı ve şifre zorunludur'); return; }

  try {
    document.getElementById('li-msg').style.display = 'none';
    const u = await KasaDB.login(user, pass);

    const ownAcc = { uid: u.uid, username: u.username, fullname: u.fullname, accType: u.accType, company: u.company || u.fullname, sector: '', taxNo: '', avatar: null, role: 'owner', isOwner: true };
    const teamAccs = getTeamAccountsFor(u.username);
    const allAccs = [ownAcc, ...teamAccs];

    if (allAccs.length > 1) {
      _pendingUser = u; _pendingRem = rem; _pendingAccounts = allAccs;
      document.getElementById('ap-greeting').textContent = 'Hoş geldiniz, ' + escHtml(u.fullname || u.username) + '! 👋';
      renderAccountPicker(allAccs);
      goAuthPane(3);
    } else {
      persistSession(u, rem); _D = null;
      addLog('system', 'auth', 'Sisteme giriş yapıldı', u.username);
      enterApp();
    }
  } catch (e) {
    showMsg('li-msg', e.message);
  }
}

function renderAccountPicker(accounts) {
  const pLabel = { owner: '👑 Hesap Sahibi', admin: '🔑 Tam Yetki', editor: '✏️ Düzenleyici', viewer: '👁 Görüntüleyici' };
  const pClass = { owner: 'badge-green', admin: 'badge-blue', editor: 'badge-yellow', viewer: 'badge-gray' };
  document.getElementById('ap-accounts').innerHTML = accounts.map((a, i) => `
        <div onclick="loginAsAccount(${i})" style="display:flex;align-items:center;gap:14px;padding:16px 18px;background:rgba(255,255,255,.04);border:1.5px solid rgba(255,255,255,.08);border-radius:14px;cursor:pointer;transition:all .22s;margin-bottom:10px"
          onmouseenter="this.style.borderColor='var(--green)';this.style.background='rgba(34,197,94,.07)'"
          onmouseleave="this.style.borderColor='rgba(255,255,255,.08)';this.style.background='rgba(255,255,255,.04)'">
          <div style="width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,var(--green),#166534);display:flex;align-items:center;justify-content:center;font-family:'Syne',sans-serif;font-size:22px;font-weight:900;color:#000;flex-shrink:0">
            ${escHtml((a.accType === 'sirket' ? (a.company || 'K') : (a.fullname || 'K')).charAt(0).toUpperCase())}
          </div>
          <div style="flex:1;min-width:0">
            <div style="font-weight:700;font-size:14px;margin-bottom:2px">${escHtml(a.accType === 'sirket' ? (a.company || a.fullname) : a.fullname)}</div>
            <div style="font-size:11px;color:var(--text-muted)">@${escHtml(a.username)} · ${a.accType === 'sirket' ? '🏢 Ŝirket' : '👤 Bireysel'}</div>
          </div>
          <span class="badge ${pClass[a.role] || 'badge-gray'}" style="font-size:10px;flex-shrink:0">${escHtml(pLabel[a.role] || a.role)}</span>
        </div>`).join('');
}

function loginAsAccount(idx) {
  const a = _pendingAccounts[idx]; const u = _pendingUser;
  if (!a || !u) { goAuthPane(0, true); return; }
  if (a.isOwner) {
    persistSession(u, _pendingRem); _D = null;
    addLog('system', 'auth', 'Sisteme giriş yapıldı', u.username);
  } else {
    SESSION = { uid: a.uid, username: u.username, fullname: u.fullname, accType: a.accType, company: a.company, sector: a.sector, taxNo: a.taxNo, avatar: u.avatar || null, teamRole: a.role, isTeamMember: true, ownUid: u.uid };
    sessionStorage.setItem('kt_sess', JSON.stringify(SESSION));
    _D = null;
    addLog('system', 'auth', 'Yetkili giriş: ' + a.company, u.username);
  }
  _pendingUser = null; _pendingAccounts = [];
  enterApp();
}

// ── TEAM MANAGEMENT (Invitation-based) ──
function sendTeamInvitation() {
  const uname = document.getElementById('team-uname').value.trim();
  const role = document.getElementById('team-perm').value;
  if (!uname) { toast('Lütfen bir kullanıcı adı giriniz', 'error'); return; }
  const target = getUsers().find(x => x.username.toLowerCase() === uname.toLowerCase());
  if (!target) { toast('Belirtilen kullanıcı adına sahip bir üye bulunamadı', 'error'); return; }
  if (target.uid === SESSION.uid) { toast('Kendinizi ekleyemezsiniz', 'error'); return; }
  const d = D();
  if (!d.teamAccess) d.teamAccess = [];
  if (d.teamAccess.find(x => x.username.toLowerCase() === uname.toLowerCase())) {
    toast('Bu kullanıcı zaten ekibinizde yer almaktadır', 'error'); return;
  }
  // Check for existing pending invitation
  if (!d.teamInvitations) d.teamInvitations = [];
  if (d.teamInvitations.find(x => x.username.toLowerCase() === uname.toLowerCase() && x.status === 'pending')) {
    toast('Bu kullanıcıya zaten bekleyen bir davet gönderilmiştir', 'error'); return;
  }
  // Create invitation and write to target user
  const inv = {
    id: cryptoToken(),
    fromUid: SESSION.uid,
    fromUsername: SESSION.username,
    fromCompany: SESSION.company || SESSION.fullname,
    toUsername: target.username,
    toUid: target.uid,
    role,
    status: 'pending',
    sentAt: new Date().toISOString()
  };
  d.teamInvitations.push(inv);
  saveD();
  // Also write to target user's data so they see it on login
  const targetData = getUserData(target.uid) || { txns: [], debts: [], goals: [], invoices: [], employees: [], logs: [], settings: { ...DEFAULT_S } };
  if (!targetData.pendingInvitations) targetData.pendingInvitations = [];
  targetData.pendingInvitations.push(inv);
  saveUserData(target.uid, targetData);
  document.getElementById('team-uname').value = '';
  addLog('edit', 'auth', 'Takım daveti gönderildi: ' + target.username, role);
  toast('Davet başarıyla gönderildi ✓ — Kullanıcının onayı bekleniyor');
  renderTeamList();
}

async function removeTeamMember(username) {
  const ok = await confirmD(username + ' adlı kullanıcının yetkisini kaldırmak istiyor musunuz?');
  if (!ok) return;
  const d = D(); d.teamAccess = (d.teamAccess || []).filter(x => x.username !== username);
  saveD(); addLog('delete', 'auth', 'Takım üyesi kaldırıldı: ' + username, '');
  toast('Kaldırıldı'); renderTeamList();
}

function renderTeamList() {
  const list = document.getElementById('team-list'); if (!list) return;
  const members = (D().teamAccess || []);
  const pending = (D().teamInvitations || []).filter(x => x.status === 'pending');
  const pLabel = { admin: '🔑 Tam Yetki', editor: '✏️ Düzenci', viewer: '👁 Görüntüleyici' };
  const pClass = { admin: 'badge-blue', editor: 'badge-yellow', viewer: 'badge-gray' };
  // Show pending invitations section
  const invSection = document.getElementById('team-invitations-section');
  if (invSection) {
    invSection.innerHTML = pending.length ? `
      <div style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px">⏳ Onay Bekleyen Davetler</div>
      ${pending.map(p => `<div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.2);border-radius:10px;margin-bottom:6px">
        <span style="font-size:16px">📩</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;font-weight:600">@${escHtml(p.toUsername)}</div>
          <div style="font-size:11px;color:var(--text-muted)">${escHtml(pLabel[p.role] || p.role)} · ${escHtml(new Date(p.sentAt).toLocaleDateString('tr-TR'))}</div>
        </div>
        <span class="badge badge-yellow" style="font-size:10px">Bekliyor</span>
        <button class="icon-btn del" onclick="cancelTeamInvitation('${escHtml(p.id)}')" title="İptal">✕</button>
      </div>`).join('')}
      <div style="border-bottom:1px solid rgba(255,255,255,.06);margin:14px 0"></div>
    ` : '';
  }
  list.innerHTML = !members.length
    ? '<div style="text-align:center;padding:16px;color:var(--text-muted);font-size:13px">Henüz yetkili kullanıcı yok</div>'
    : members.map(m => `<div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05)">
          <div style="width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--blue),var(--purple));display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0">${escHtml((m.fullname || m.username).charAt(0).toUpperCase())}</div>
          <div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:600">${escHtml(m.fullname || m.username)}</div><div style="font-size:11px;color:var(--text-muted)">@${escHtml(m.username)}</div></div>
          <span class="badge ${pClass[m.role] || 'badge-gray'}" style="font-size:10px">${escHtml(pLabel[m.role] || m.role)}</span>
          <button class="icon-btn del" onclick="removeTeamMember('${escHtml(m.username)}')" title="Kaldır">🗑</button>
        </div>`).join('');
}

function cancelTeamInvitation(invId) {
  const d = D();
  if (!d.teamInvitations) return;
  const inv = d.teamInvitations.find(x => x.id === invId);
  if (!inv) return;
  inv.status = 'cancelled';
  // Also update target user's pending invitations
  const targetData = getUserData(inv.toUid);
  if (targetData && targetData.pendingInvitations) {
    const pi = targetData.pendingInvitations.find(x => x.id === invId);
    if (pi) { pi.status = 'cancelled'; saveUserData(inv.toUid, targetData); }
  }
  saveD();
  toast('İptal edildi');
  renderTeamList();
}

async function doRegister() {
  const user = document.getElementById('r-user').value.trim();
  const email = user.includes('@') ? user : ''; // if username is email
  const p1 = document.getElementById('r-pass1').value;
  const p2 = document.getElementById('r-pass2').value;
  const terms = document.getElementById('r-terms').checked;
  const fname = document.getElementById('r-fname').value.trim();
  const lname = document.getElementById('r-lname').value.trim();
  const phone = document.getElementById('r-phone').value.trim();
  const birthdate = document.getElementById('r-birthdate').value;
  const secQ = document.getElementById('r-secq').value;
  const secA = document.getElementById('r-seca').value.trim();

  const fullname = fname + ' ' + lname;

  if (!user) { showMsg('reg-msg', 'Kullanıcı adı / e-posta zorunludur'); return; }

  // Strict Validation
  const valData = validatePersonalData({ fullname, email: user.includes('@') ? user : user + '@mail.com', phone, birthdate });
  if (!valData.ok) { showMsg('reg-msg', valData.msg); return; }

  const valPw = validatePassword(p1);
  if (!valPw.ok) { showMsg('reg-msg', valPw.msg); return; }
  if (p1 !== p2) { showMsg('reg-msg', 'Girilen parolalar birbiriyle eşleşmiyor'); return; }

  if (!secQ || !secA) { showMsg('reg-msg', 'Güvenlik sorusu ve cevabı zorunludur'); return; }

  if (!terms) {
    showMsg('reg-msg', 'Devam edebilmek için Kullanım Koşulları\'nı okuduğunuzu onaylamanız gerekmektedir'); return;
  }

  const nu = {
    username: user,
    fullname: fullname,
    accType: regAcct,
    company: regAcct === 'sirket' ? document.getElementById('r-company').value.trim() : '',
    phone: phone,
    birthdate: birthdate,
    email: email,
    securityQuestion: secQ,
    securityAnswerHash: await hashAnswer(secA)
  };

  try {
    document.getElementById('reg-msg').style.display = 'none';
    await KasaDB.register(nu, p1);
    showMsg('reg-msg', 'Hesabınız başarıyla oluşturuldu. Giriş yapabilirsiniz.', 'ok');
    setTimeout(() => { goAuthPane(0); document.getElementById('li-user').value = user; }, 1800);
  } catch (e) {
    showMsg('reg-msg', e.message);
  }
}

// ── FORGOT PASSWORD 3-STEP WIZARD ──
let _fpUser = null;
let _fpStep = 1;

function fpGo(step) {
  _fpStep = step;
  document.getElementById('fp-s1').style.display = step === 1 ? 'block' : 'none';
  document.getElementById('fp-s2').style.display = step === 2 ? 'block' : 'none';
  document.getElementById('fp-s3').style.display = step === 3 ? 'block' : 'none';
  document.getElementById('fp-msg').style.display = 'none';
}

async function fpSubmit1() {
  const u = document.getElementById('fp-user').value.trim();
  if (!u) { showMsg('fp-msg', 'Lütfen kullanıcı adı girin'); return; }
  try {
    const q = await KasaDB.getSecurityQuestion(u);
    _fpUser = u;
    document.getElementById('fp-qtext').textContent = q;
    fpGo(2);
  } catch (e) {
    showMsg('fp-msg', e.message);
  }
}

async function fpSubmit2() {
  const ans = document.getElementById('fp-ans').value.trim();
  if (!ans) { showMsg('fp-msg', 'Cevabı giriniz'); return; }
  try {
    const res = await KasaDB.verifySecurityAnswer(_fpUser, ans);
    if (!res.ok) throw new Error('Güvenlik sorusu cevabı yanlış');
    showMsg('fp-msg', 'Güvenlik adımı geçildi! Yeni şifrenizi belirleyin.', 'ok');
    fpGo(3);
  } catch (e) {
    showMsg('fp-msg', e.message);
  }
}

async function fpSubmit3() {
  const p1 = document.getElementById('fp-p1').value;
  const p2 = document.getElementById('fp-p2').value;
  const valPw = validatePassword(p1);
  if (!valPw.ok) { showMsg('fp-msg', valPw.msg); return; }
  if (p1 !== p2) { showMsg('fp-msg', 'Şifreler uyuşmuyor'); return; }
  try {
    await KasaDB.resetPwAnon(p1);
    showMsg('fp-msg', 'Şifreniz başarıyla güncellendi. Giriş yapabilirsiniz.', 'ok');
    setTimeout(() => { goAuthPane(0); }, 2000);
  } catch (e) {
    showMsg('fp-msg', 'Hata: ' + e.message);
  }
}

// ── PERMISSION CHECK ──
// Returns true if the current session has permission to perform write operations
function canWrite() {
  if (!SESSION) return false;
  // Team members with 'viewer' role cannot write
  if (SESSION.isTeamMember && SESSION.teamRole === 'viewer') return false;
  return true;
}
function canAdmin() {
  if (!SESSION) return false;
  if (SESSION.isTeamMember && SESSION.teamRole !== 'admin') return false;
  return true;
}
function requireWrite(action) {
  if (!canWrite()) {
    toast('Bu hesapta yalnızca görüntüleme yetkiniz bulunmaktadır. Bu işlemi gerçekleştiremezsiniz.', 'error');
    return false;
  }
  return true;
}

async function doLogout(skipConfirm = false) {
  if (!skipConfirm) {
    const ok = await showConfirm('Çıkış yapmak istediğinizden emin misiniz?', { title: 'Çıkış', confirmText: 'Evet, Çık', danger: false });
    if (!ok) return;
  }
  // Clean up timers and event listeners before nulling SESSION
  _stopIdleTimer();
  if (_sessionWatcherId) { clearInterval(_sessionWatcherId); _sessionWatcherId = null; }
  // Mark this device session as logged out
  const d = D();
  if (d && d.deviceSessions && SESSION) {
    const ds = d.deviceSessions.find(s => s.sessionId === SESSION.sessionId);
    if (ds) { ds.isActive = false; ds.lastLogoutAt = new Date().toISOString(); saveD(); }
  }
  if (SESSION) addLog('system', 'auth', 'Çıkış yapıldı', SESSION.username);
  sessionStorage.removeItem('kt_sess');
  // remToken artık kullanılmıyor (MongoDB cookie session)
  SESSION = null;
  _D = null;
  // Restore default CSS variables
  document.documentElement.style.setProperty('--green', '#22c55e');
  document.documentElement.style.setProperty('--green-dim', 'rgba(34,197,94,.13)');
  document.documentElement.style.setProperty('--sidebar-w', '264px');
  try { await KasaDB.logout(); } catch (e) { }
  window.location.href = 'index.html';
}

/** Profile Completion Gatekeeper */
function checkProfileCompletion() {
  if (!SESSION) return;
  if (!SESSION.profileComplete || !SESSION.phone || !SESSION.birthdate || !SESSION.fullname) {
    document.getElementById('pc-fname').value = SESSION.fullname && !SESSION.fullname.includes('undefined') ? SESSION.fullname.split(' ')[0] : '';
    document.getElementById('pc-lname').value = SESSION.fullname && !SESSION.fullname.includes('undefined') ? SESSION.fullname.split(' ').slice(1).join(' ') : '';
    document.getElementById('pc-phone').value = SESSION.phone || '';
    document.getElementById('pc-birthdate').value = SESSION.birthdate || '';
    document.getElementById('pc-email').value = SESSION.email || '';
    document.getElementById('profile-completion-modal').classList.add('open');
    return false;
  }
  return true;
}

async function saveProfileCompletion() {
  const fname = document.getElementById('pc-fname').value.trim();
  const lname = document.getElementById('pc-lname').value.trim();
  const phone = document.getElementById('pc-phone').value.trim();
  const birthdate = document.getElementById('pc-birthdate').value;
  const email = document.getElementById('pc-email').value.trim();

  const fullname = fname + ' ' + lname;
  const val = validatePersonalData({ fullname, email, phone, birthdate });
  if (!val.ok) { toast(val.msg, 'error'); return; }

  try {
    await KasaDB.updateProfile({ fullname, phone, birthdate, email, profileComplete: true });
    SESSION.fullname = fullname;
    SESSION.phone = phone;
    SESSION.birthdate = birthdate;
    SESSION.email = email;
    SESSION.profileComplete = true;
    sessionStorage.setItem('kt_sess', JSON.stringify(SESSION));

    document.getElementById('profile-completion-modal').classList.remove('open');
    toast('Profiliniz güncellendi. Teşekkürler!', 'ok');
    initApp();
  } catch (e) {
    toast('Hata: ' + e.message, 'error');
  }
}

function enterApp() {
  // Stop the auth slide show to save CPU
  if (_slideInterval) { clearInterval(_slideInterval); _slideInterval = null; }
  const shell = document.getElementById('auth-shell');
  shell.classList.add('out');
  setTimeout(() => { shell.style.display = 'none'; }, 450);
  document.getElementById('app').style.display = 'block';

  if (checkProfileCompletion()) {
    initApp();
  }
}

// ══════════════════════════════════════════════════════════
//  NAVIGATION — different menus per account type
// ══════════════════════════════════════════════════════════
const NAV_BIREYSEL = [
  { id: 'dashboard', icon: '🏠', label: 'Dashboard' },
  { id: 'transactions', icon: '💸', label: 'İşlemler' },
  { id: 'debts', icon: '🔴', label: 'Borçlar', badge: 'debt-badge' },
  { id: 'credits', icon: '🏦', label: 'Kredi & Taksit', badge: 'credit-badge' },
  { id: 'subscriptions', icon: '🔄', label: 'Abonelikler', badge: 'subs-badge' },
  { id: 'analytics', icon: '📊', label: 'Analitik' },
  { id: 'goals', icon: '🎯', label: 'Hedefler' },
  { sep: 'Sistem' },
  { id: 'log', icon: '📋', label: 'Aktivite Logu' },
  { id: 'settings', icon: '⚙️', label: 'Ayarlar' },
];
const NAV_SIRKET = [
  { id: 'dashboard', icon: '🏠', label: 'Ana Panel' },
  { id: 'transactions', icon: '💸', label: 'Muhasebe' },
  { id: 'invoices', icon: '🧾', label: 'Faturalar', badge: 'inv-badge' },
  { id: 'customers', icon: '🤝', label: 'Müşteri & Tedarikçi' },
  { id: 'stock', icon: '📦', label: 'Stok & Ürünler' },
  { id: 'projects', icon: '🗂️', label: 'Projeler', badge: 'proj-badge' },
  { id: 'payroll', icon: '💰', label: 'Bordro & Personel' },
  { id: 'employees', icon: '👥', label: 'Çalışanlar' },
  { id: 'debts', icon: '🔴', label: 'Cari Hesaplar', badge: 'debt-badge' },
  { id: 'analytics', icon: '📊', label: 'Raporlar' },
  { id: 'goals', icon: '🎯', label: 'Hedefler' },
  { sep: 'Yönetim' },
  { id: 'log', icon: '📋', label: 'Denetim Kaydı' },
  { id: 'settings', icon: '⚙️', label: 'Sistem Ayarları' },
];

const CATS_BIREYSEL = ['Satış', 'Alış', 'Gider', 'Maaş', 'Kira', 'Fatura', 'Yatırım', 'Diğer'];
const CATS_SIRKET = ['Satış Geliri', 'Hizmet Geliri', 'Malzeme Alımı', 'Personel Gideri', 'Kira', 'Fatura/Abonelik', 'Pazarlama', 'Vergi', 'KDV Ödemesi', 'İşletme Gideri', 'Yatırım', 'Diğer'];

let curPage = 'dashboard';
const charts = {};

function renderNav() {
  const items = isSirket() ? NAV_SIRKET : NAV_BIREYSEL;
  let html = items.map(item => {
    if (item.sep) return `<div class="nav-section">${item.sep}</div>`;
    return `<div class="nav-item${item.id === curPage ? ' active' : ''}" onclick="goPage('${item.id}')">
      <span class="nav-icon">${item.icon}</span>${item.label}
      ${item.badge ? `<span class="nav-badge" id="${item.badge}" style="display:none">0</span>` : ''}
    </div>`;
  }).join('');

  if (SESSION && SESSION.username === 'kasalyadmin2026@gmail.com') {
    html += `<div class="nav-section">Geliştirici</div>`;
    html += `<div class="nav-item${curPage === 'admin' ? ' active' : ''}" onclick="goPage('admin')">
      <span class="nav-icon">🛡️</span>Kasaly Developer
    </div>`;
  }
  document.getElementById('main-nav').innerHTML = html;
}

function goPage(id) {
  curPage = id;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const pg = document.getElementById('page-' + id);
  if (pg) pg.classList.add('active');
  renderNav();
  const renders = { dashboard: renderDash, transactions: renderTable, debts: renderDebts, analytics: renderCharts, goals: renderGoals, invoices: renderInvoices, employees: renderEmployees, log: renderLog, settings: renderSettings, admin: renderAdmin, credits: renderCredits, subscriptions: renderSubscriptions, customers: renderCustomers, stock: renderStock, projects: renderProjects, payroll: renderPayroll };
  if (renders[id]) renders[id]();
}

// ══════════════════════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════════════════════
function renderDash() {
  const d = D(); const now = new Date(); const m = now.getMonth(), y = now.getFullYear();
  const todayStr = today();
  const isSC = isSirket();

  document.getElementById('dash-title').textContent = isSC ? 'Ana Panel' : 'Dashboard';
  document.getElementById('bal-lbl').textContent = isSC ? '💼 Güncel Ciro Bakiyesi' : '📦 Anlık Kasa Bakiyesi';

  if (isSC && SESSION.company) {
    document.getElementById('company-banner').style.display = 'flex';
    document.getElementById('cb-name').textContent = SESSION.company;
    document.getElementById('cb-sector').textContent = SESSION.sector || '';
  } else document.getElementById('company-banner').style.display = 'none';

  document.getElementById('dash-bal').textContent = fmt(bal());
  document.getElementById('dash-upd').textContent = 'Son güncelleme: ' + now.toLocaleString('tr-TR', { day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  document.getElementById('dash-date').textContent = now.toLocaleDateString('tr-TR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

  const todT = d.txns.filter(t => t.date === todayStr);
  const monT = d.txns.filter(t => { const dd = new Date(t.date); return dd.getMonth() === m && dd.getFullYear() === y; });
  const sum = (arr, type) => arr.filter(t => t.type === type).reduce((a, t) => a + t.amount, 0);

  document.getElementById('d-ti').textContent = fmt(sum(todT, 'income'));
  document.getElementById('d-to').textContent = fmt(sum(todT, 'expense'));
  document.getElementById('d-mi').textContent = fmt(sum(monT, 'income'));
  document.getElementById('d-mo').textContent = fmt(sum(monT, 'expense'));
  document.getElementById('d-ti-c').textContent = todT.filter(t => t.type === 'income').length + ' işlem';
  document.getElementById('d-to-c').textContent = todT.filter(t => t.type === 'expense').length + ' işlem';
  document.getElementById('d-mi-c').textContent = monT.filter(t => t.type === 'income').length + ' işlem';
  document.getElementById('d-mo-c').textContent = monT.filter(t => t.type === 'expense').length + ' işlem';

  document.getElementById('reminder-bar').style.display = (d.settings.reminder && !todT.length) ? 'flex' : 'none';

  // Company KPIs
  const kpiEl = document.getElementById('company-kpis');
  if (isSC) {
    kpiEl.style.display = 'block';
    const invs = d.invoices || [];
    const pendInv = invs.filter(i => i.status === 'pending').reduce((a, i) => a + i.totalAmount, 0);
    const overInv = invs.filter(i => i.status === 'overdue').reduce((a, i) => a + i.totalAmount, 0);
    const totalKdv = d.txns.filter(t => t.kdv > 0).reduce((a, t) => a + (t.amount * (t.kdv / 100)), 0);
    const netProfit = sum(monT, 'income') - sum(monT, 'expense');
    const emps = d.employees || [];
    const totalSalary = emps.filter(e => e.status === 'active').reduce((a, e) => a + (e.salary || 0), 0);
    kpiEl.innerHTML = `<div class="kpi-grid">
      <div class="card kpi-card"><div class="kpi-val" style="color:var(--yellow)">${fmt(pendInv)}</div><div class="kpi-lbl">⏳ Tahsilat Bekleyen</div></div>
      <div class="card kpi-card"><div class="kpi-val" style="color:${netProfit >= 0 ? 'var(--green)' : 'var(--red)'}">${fmt(netProfit)}</div><div class="kpi-lbl">💹 Aylık Net Kâr</div></div>
      <div class="card kpi-card"><div class="kpi-val" style="color:var(--cyan)">${fmt(totalKdv)}</div><div class="kpi-lbl">📋 KDV Toplam</div></div>
      <div class="card kpi-card"><div class="kpi-val" style="color:var(--red)">${fmt(totalSalary)}</div><div class="kpi-lbl">👥 Aylık Maaş Gideri</div></div>
      <div class="card kpi-card"><div class="kpi-val" style="color:var(--red)">${fmt(overInv)}</div><div class="kpi-lbl">⚠️ Vadesi Geçen Fatura</div></div>
      <div class="card kpi-card"><div class="kpi-val">${emps.filter(e => e.status === 'active').length}</div><div class="kpi-lbl">👤 Aktif Çalışan</div></div>
    </div>`;
  } else kpiEl.style.display = 'none';

  // Debt quick row
  const ad = d.debts.filter(x => x.status === 'active');
  const owe = ad.filter(x => x.dtype === 'owe').reduce((a, x) => a + (x.amount - (x.paid || 0)), 0);
  const lend = ad.filter(x => x.dtype === 'lend').reduce((a, x) => a + (x.amount - (x.paid || 0)), 0);
  document.getElementById('dash-debt-row').innerHTML = ad.length ? `
    <div class="card quick-card" style="background:var(--red-dim);border:1px solid rgba(239,68,68,.18)"><div style="font-size:10px;color:var(--red);font-weight:700;text-transform:uppercase;margin-bottom:5px">🔴 Kalan Borcum</div><div style="font-family:'Syne',sans-serif;font-size:20px;font-weight:800;color:var(--red)">${fmt(owe)}</div></div>
    <div class="card quick-card" style="background:var(--green-dim);border:1px solid rgba(34,197,94,.18)"><div style="font-size:10px;color:var(--green);font-weight:700;text-transform:uppercase;margin-bottom:5px">🟢 Kalan Alacağım</div><div style="font-family:'Syne',sans-serif;font-size:20px;font-weight:800;color:var(--green)">${fmt(lend)}</div></div>` : '';

  // Recent txns
  const recent = [...d.txns].sort((a, b) => b.id - a.id).slice(0, 6);
  document.getElementById('recent-txns').innerHTML = recent.length ? recent.map(t => `
    <div class="txn-item"><div class="txn-icon ${t.type}">${t.type === 'income' ? '📥' : '📤'}</div>
    <div class="txn-info"><div class="txn-name">${escHtml(t.desc) || '—'}</div><div class="txn-cat">${escHtml(t.cat)}${t.dept ? ' · ' + escHtml(t.dept) : ''} · ${escHtml(t.date)}</div></div>
    <div class="txn-amount ${t.type}">${t.type === 'income' ? '+' : '-'}${fmt(t.amount)}</div></div>`).join('')
    : '<div class="empty-state" style="padding:24px"><div class="es-icon">📭</div><p>İşlem yok</p></div>';

  // Week chart
  const wL = [], wI = [], wO = [];
  for (let i = 6; i >= 0; i--) { const dd = new Date(); dd.setDate(dd.getDate() - i); const ds = dd.toISOString().split('T')[0]; wL.push(dd.toLocaleDateString('tr-TR', { weekday: 'short' })); const dt = d.txns.filter(t => t.date === ds); wI.push(dt.filter(t => t.type === 'income').reduce((a, t) => a + t.amount, 0)); wO.push(dt.filter(t => t.type === 'expense').reduce((a, t) => a + t.amount, 0)); }
  if (charts.week) {
    charts.week.data.labels = wL;
    charts.week.data.datasets[0].data = wI;
    charts.week.data.datasets[1].data = wO;
    charts.week.update();
  } else {
    charts.week = new Chart(document.getElementById('weekChart'), { type: 'bar', data: { labels: wL, datasets: [{ label: 'Giriş', data: wI, backgroundColor: 'rgba(34,197,94,.65)', borderRadius: 5 }, { label: 'Çıkış', data: wO, backgroundColor: 'rgba(239,68,68,.65)', borderRadius: 5 }] }, options: { responsive: true, plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } }, scales: { x: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#64748b' } }, y: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#64748b', callback: v => cur() + v.toLocaleString('tr-TR') } } } } });
  }
}

// ══════════════════════════════════════════════════════════
//  TRANSACTIONS
// ══════════════════════════════════════════════════════════
let curTxnType = 'income';

function refreshCatFilter() {
  const sel = document.getElementById('txn-cat-f'); if (!sel) return;
  const cats = isSirket() ? CATS_SIRKET : CATS_BIREYSEL;
  sel.innerHTML = '<option value="">Tüm Kategoriler</option>' + cats.map(c => `<option>${c}</option>`).join('');
}

function openTxnModal(type, id = null) {
  const isSC = isSirket();
  curTxnType = type;
  ['f-amount', 'f-desc', 'f-note'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('f-date').value = today();
  document.getElementById('f-id').value = id || '';
  document.getElementById('txn-modal-title').textContent = id ? 'İşlem Düzenle' : 'İşlem Ekle';
  // Category options
  const cats = isSC ? CATS_SIRKET : CATS_BIREYSEL;
  document.getElementById('f-cat').innerHTML = cats.map(c => `<option>${c}</option>`).join('');
  // Company extras
  document.getElementById('f-dept-group').style.display = isSC ? 'block' : 'none';
  document.getElementById('f-kdv-group').style.display = isSC ? 'block' : 'none';
  if (id) {
    const t = D().txns.find(x => x.id === id); if (!t) return;
    curTxnType = t.type;
    document.getElementById('f-amount').value = t.amount;
    document.getElementById('f-desc').value = t.desc || '';
    document.getElementById('f-note').value = t.note || '';
    document.getElementById('f-cat').value = t.cat;
    document.getElementById('f-date').value = t.date;
    if (isSC) { document.getElementById('f-dept').value = t.dept || 'Genel'; document.getElementById('f-kdv').value = t.kdv || 0; }
  }
  setTxnType(curTxnType);
  document.getElementById('txn-modal').classList.add('open');
}

function setTxnType(t) { curTxnType = t; document.getElementById('type-income').classList.toggle('active', t === 'income'); document.getElementById('type-expense').classList.toggle('active', t === 'expense'); }

function saveTxn() {
  if (!requireWrite()) return;
  const rawAmt = parseFloat(document.getElementById('f-amount').value);
  const amount = Math.round((isNaN(rawAmt) ? 0 : rawAmt) * 100) / 100;
  const desc = document.getElementById('f-desc').value.trim();
  const cat = document.getElementById('f-cat').value;
  const date = document.getElementById('f-date').value;
  const note = document.getElementById('f-note').value.trim();
  const dept = isSirket() ? document.getElementById('f-dept').value : '';
  const kdv = isSirket() ? parseInt(document.getElementById('f-kdv').value) || 0 : 0;
  if (!amount || amount <= 0) { toast('Geçerli bir tutar giriniz', 'error'); return; }
  if (!date) { toast('Tarih zorunludur', 'error'); return; }
  const maxAmount = isSirket() ? 99_999_999 : 999_999;
  if (amount > maxAmount) { toast(`Maksimum tutar: ${fmt(maxAmount)}`, 'error'); return; }
  const d = D(); const eid = document.getElementById('f-id').value;
  if (eid) {
    // Use Number() instead of parseInt() to handle large IDs without overflow
    const numId = Number(eid);
    const idx = d.txns.findIndex(x => x.id === numId);
    if (idx > -1) d.txns[idx] = { ...d.txns[idx], type: curTxnType, amount, desc, cat, date, note, dept, kdv };
    addLog('edit', 'txn', `İşlem düzenlendi: ${desc || cat}`, fmt(amount)); toast('Güncellendi ✓');
  } else {
    d.txns.push({ id: uid(), type: curTxnType, amount, desc, cat, date, note, dept, kdv });
    addLog('add', 'txn', `${curTxnType === 'income' ? 'Giriş' : 'Çıkış'} eklendi: ${desc || cat}`, fmt(amount)); toast('Eklendi ✓');
  }
  saveD(); closeModal('txn-modal'); renderTable(); if (curPage === 'dashboard') renderDash();
}

async function deleteTxn(id) {
  const ok = await confirmD('Bu işlemi silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const t = d.txns.find(x => x.id === id);
  addLog('delete', 'txn', `İşlem silindi: ${t ? t.desc || t.cat : '?'}`, t ? fmt(t.amount) : '');
  d.txns = d.txns.filter(x => x.id !== id); saveD(); renderTable(); if (curPage === 'dashboard') renderDash(); toast('Silindi');
}

function clearTxnF() { document.getElementById('txn-search').value = ''; document.getElementById('txn-type-f').value = ''; document.getElementById('txn-cat-f').value = ''; const n = new Date(); document.getElementById('txn-month-f').value = `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}`; renderTable(); }

function renderTable() {
  const isSC = isSirket();
  refreshCatFilter();
  const search = document.getElementById('txn-search').value.toLowerCase();
  const tf = document.getElementById('txn-type-f').value;
  const cf = document.getElementById('txn-cat-f').value;
  const mf = document.getElementById('txn-month-f').value;
  let data = [...D().txns].sort((a, b) => b.id - a.id);
  if (search) data = data.filter(t => (t.desc || '').toLowerCase().includes(search) || (t.cat || '').toLowerCase().includes(search));
  if (tf) data = data.filter(t => t.type === tf);
  if (cf) data = data.filter(t => t.cat === cf);
  if (mf) data = data.filter(t => t.date.startsWith(mf));
  // Show/hide company columns
  document.getElementById('th-dept').style.display = isSC ? '' : 'none';
  document.getElementById('th-kdv').style.display = isSC ? '' : 'none';
  const tbody = document.getElementById('txn-tbody'), empty = document.getElementById('txn-empty'), summary = document.getElementById('txn-summary');
  if (!data.length) { tbody.innerHTML = ''; empty.style.display = 'block'; summary.innerHTML = ''; return; }
  empty.style.display = 'none';
  tbody.innerHTML = data.map(t => `<tr>
    <td style="color:var(--text-muted);font-size:12px">${escHtml(t.date)}</td>
    <td><div style="font-weight:500">${escHtml(t.desc) || '<span style="color:var(--text-muted)">—</span>'}</div>${t.note ? `<div style="font-size:11px;color:var(--text-muted)">${escHtml(t.note)}</div>` : ''}</td>
    <td><span class="badge badge-blue">${escHtml(t.cat)}</span></td>
    ${isSC ? `<td>${t.dept ? `<span class="dept-badge">${escHtml(t.dept)}</span>` : ''}</td>` : ''}
    <td><span class="badge ${t.type === 'income' ? 'badge-green' : 'badge-red'}">${t.type === 'income' ? '📥 Giriş' : '📤 Çıkış'}</span></td>
    ${isSC ? `<td>${t.kdv ? `<span class="badge badge-cyan">KDV %${t.kdv}</span>` : ''}</td>` : ''}
    <td style="text-align:right;font-family:'Syne',sans-serif;font-weight:700;color:${t.type === 'income' ? 'var(--green)' : 'var(--red)'}">
      ${t.type === 'income' ? '+' : '-'}${fmt(t.amount)}</td>
    <td><div class="action-btns"><button class="icon-btn edit" onclick="openTxnModal('${t.type}',${t.id})">✏️</button><button class="icon-btn del" onclick="deleteTxn(${t.id})">🗑</button></div></td>
  </tr>`).join('');
  const totIn = data.filter(t => t.type === 'income').reduce((a, t) => a + t.amount, 0);
  const totOut = data.filter(t => t.type === 'expense').reduce((a, t) => a + t.amount, 0);
  const net = totIn - totOut;
  summary.innerHTML = `<span style="color:var(--green)">Giriş: <strong>${fmt(totIn)}</strong></span><span style="color:var(--red)">Çıkış: <strong>${fmt(totOut)}</strong></span><span>Net: <strong style="color:${net >= 0 ? 'var(--green)' : 'var(--red)'}">${fmt(net)}</strong></span><span style="color:var(--text-muted)">${data.length} kayıt</span>`;
}

// ══════════════════════════════════════════════════════════
//  INVOICES (Şirket only)
// ══════════════════════════════════════════════════════════
let curInvType = 'sales';
function setInvType(t) { curInvType = t; document.getElementById('itype-sales').classList.toggle('active', t === 'sales'); document.getElementById('itype-purchase').classList.toggle('active', t === 'purchase'); }

function openInvoiceModal(id = null) {
  curInvType = 'sales';
  ['inv-party', 'inv-no', 'inv-amount', 'inv-desc'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('inv-date').value = today(); document.getElementById('inv-due').value = '';
  document.getElementById('inv-kdv').value = '18'; document.getElementById('inv-status').value = 'pending';
  document.getElementById('inv-id').value = id || '';
  document.getElementById('inv-modal-title').textContent = id ? 'Fatura Düzenle' : 'Fatura Ekle';
  if (id) {
    const inv = (D().invoices || []).find(x => x.id === id); if (!inv) return;
    curInvType = inv.itype;
    document.getElementById('inv-party').value = inv.party;
    document.getElementById('inv-no').value = inv.no;
    document.getElementById('inv-amount').value = inv.amount;
    document.getElementById('inv-kdv').value = inv.kdv;
    document.getElementById('inv-date').value = inv.date;
    document.getElementById('inv-due').value = inv.due || '';
    document.getElementById('inv-status').value = inv.status;
    document.getElementById('inv-desc').value = inv.desc || '';
  }
  setInvType(curInvType);
  document.getElementById('invoice-modal').classList.add('open');
}

function saveInvoice() {
  if (!requireWrite()) return;
  const party = document.getElementById('inv-party').value.trim();
  const rawAmt = parseFloat(document.getElementById('inv-amount').value);
  const amount = Math.round((isNaN(rawAmt) ? 0 : rawAmt) * 100) / 100;
  const kdv = parseInt(document.getElementById('inv-kdv').value) || 0;
  if (!party) { toast('Müşteri/Tedarikçi adı zorunludur', 'error'); return; }
  if (!amount || amount <= 0) { toast('Tutar zorunludur', 'error'); return; }
  if (amount > 99_999_999) { toast('Maksimum tutar: ' + fmt(99_999_999), 'error'); return; }
  const d = D(); if (!d.invoices) d.invoices = [];

  const eid = document.getElementById('inv-id').value;
  const totalAmount = Math.round(amount * (1 + kdv / 100) * 100) / 100;
  const obj = {
    id: eid ? Number(eid) : uid(), itype: curInvType,
    party, no: document.getElementById('inv-no').value.trim() || 'FTR-' + uid().toString().slice(-4),
    amount, kdv, totalAmount,
    date: document.getElementById('inv-date').value,
    due: document.getElementById('inv-due').value,
    status: document.getElementById('inv-status').value,
    desc: document.getElementById('inv-desc').value.trim()
  };
  if (eid) { d.invoices[d.invoices.findIndex(x => x.id === Number(eid))] = obj; addLog('edit', 'invoice', 'Fatura düzenlendi: ' + party, fmt(totalAmount)); toast('Güncellendi ✓'); }
  else { d.invoices.push(obj); addLog('add', 'invoice', 'Fatura eklendi: ' + party, fmt(totalAmount)); toast('Eklendi ✓'); }
  saveD(); closeModal('invoice-modal'); renderInvoices(); if (curPage === 'dashboard') renderDash();
}

async function deleteInvoice(id) {
  const ok = await confirmD('Bu faturayı silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const inv = d.invoices.find(x => x.id === id);
  addLog('delete', 'invoice', 'Fatura silindi: ' + (inv ? inv.party : '?'), '');
  d.invoices = d.invoices.filter(x => x.id !== id); saveD(); renderInvoices(); if (curPage === 'dashboard') renderDash(); toast('Silindi');
}

function renderInvoices() {
  const d = D(); const invs = d.invoices || [];
  const search = document.getElementById('inv-search').value.toLowerCase();
  const sf = document.getElementById('inv-status-f').value;
  let data = [...invs].sort((a, b) => b.id - a.id);
  if (search) data = data.filter(i => (i.party || '').toLowerCase().includes(search) || (i.no || '').toLowerCase().includes(search));
  if (sf) data = data.filter(i => i.status === sf);
  const sum = (s) => invs.filter(i => i.status === s).reduce((a, i) => a + i.totalAmount, 0);
  document.getElementById('inv-paid-tot').textContent = fmt(sum('paid'));
  document.getElementById('inv-pend-tot').textContent = fmt(sum('pending'));
  document.getElementById('inv-over-tot').textContent = fmt(sum('overdue'));
  const tbody = document.getElementById('inv-tbody'), empty = document.getElementById('inv-empty');
  if (!data.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  const sLabels = { paid: '<span class="badge badge-green">✅ Ödendi</span>', pending: '<span class="badge badge-yellow">⏳ Bekliyor</span>', overdue: '<span class="badge badge-red">⚠️ Vadesi Geçti</span>' };
  tbody.innerHTML = data.map(i => `<tr>
    <td style="font-size:12px;font-weight:600">${escHtml(i.no)}</td>
    <td style="font-weight:500">${escHtml(i.party)}</td>
    <td><span class="badge ${i.itype === 'sales' ? 'badge-green' : 'badge-blue'}">${i.itype === 'sales' ? '📤 Satış' : '📥 Alış'}</span></td>
    <td style="font-size:12px;color:var(--text-muted)">${escHtml(i.date)}</td>
    <td style="font-size:12px;color:var(--text-muted)">${escHtml(i.due) || '—'}</td>
    <td>${i.kdv ? `<span class="badge badge-cyan">%${i.kdv}</span>` : ''}</td>
    <td style="text-align:right;font-family:'Syne',sans-serif;font-weight:700">${fmt(i.totalAmount)}</td>
    <td>${sLabels[i.status] || ''}</td>
    <td><div class="action-btns"><button class="icon-btn edit" onclick="openInvoiceModal(${i.id})">✏️</button><button class="icon-btn del" onclick="deleteInvoice(${i.id})">🗑</button></div></td>
  </tr>`).join('');
}

// ══════════════════════════════════════════════════════════
//  EMPLOYEES (Şirket only)
// ══════════════════════════════════════════════════════════
function openEmpModal(id = null) {
  ['emp-fname', 'emp-lname', 'emp-pos', 'emp-email'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('emp-salary').value = '';
  document.getElementById('emp-start').value = today();
  document.getElementById('emp-dept').value = 'Genel';
  document.getElementById('emp-status').value = 'active';
  document.getElementById('emp-id').value = id || '';
  document.getElementById('emp-modal-title').textContent = id ? 'Çalışan Düzenle' : 'Çalışan Ekle';
  if (id) {
    const e = (D().employees || []).find(x => x.id === id); if (!e) return;
    document.getElementById('emp-fname').value = e.fname; document.getElementById('emp-lname').value = e.lname;
    document.getElementById('emp-pos').value = e.pos; document.getElementById('emp-dept').value = e.dept;
    document.getElementById('emp-salary').value = e.salary; document.getElementById('emp-start').value = e.start;
    document.getElementById('emp-email').value = e.email || ''; document.getElementById('emp-status').value = e.status;
  }
  document.getElementById('emp-modal').classList.add('open');
}

function saveEmployee() {
  if (!requireWrite()) return;
  const fname = document.getElementById('emp-fname').value.trim();
  const lname = document.getElementById('emp-lname').value.trim();
  const salary = parseFloat(document.getElementById('emp-salary').value) || 0;
  if (!fname || !lname) { toast('Ad ve soyad zorunludur', 'error'); return; }
  if (salary > 9_999_999) { toast('Maksimum maaş: ' + fmt(9_999_999), 'error'); return; }
  const d = D(); if (!d.employees) d.employees = [];
  const eid = document.getElementById('emp-id').value;
  const obj = { id: eid ? Number(eid) : uid(), fname, lname, pos: document.getElementById('emp-pos').value.trim(), dept: document.getElementById('emp-dept').value, salary, start: document.getElementById('emp-start').value, email: document.getElementById('emp-email').value.trim(), status: document.getElementById('emp-status').value };
  if (eid) { d.employees[d.employees.findIndex(x => x.id === Number(eid))] = obj; addLog('edit', 'employee', 'Çalışan düzenlendi: ' + fname + ' ' + lname, obj.pos); toast('Güncellendi ✓'); }
  else { d.employees.push(obj); addLog('add', 'employee', 'Çalışan eklendi: ' + fname + ' ' + lname, obj.pos); toast('Eklendi ✓'); }
  saveD(); closeModal('emp-modal'); renderEmployees(); if (curPage === 'dashboard') renderDash();
}

async function deleteEmployee(id) {
  const ok = await confirmD('Bu çalışanı silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const e = d.employees.find(x => x.id === id);
  addLog('delete', 'employee', 'Çalışan silindi: ' + (e ? e.fname + ' ' + e.lname : '?'), '');
  d.employees = d.employees.filter(x => x.id !== id); saveD(); renderEmployees(); if (curPage === 'dashboard') renderDash(); toast('Silindi');
}

function renderEmployees() {
  const d = D(); const emps = d.employees || [];
  const total = emps.length;
  const totalSalary = emps.filter(e => e.status === 'active').reduce((a, e) => a + (e.salary || 0), 0);
  const depts = [...new Set(emps.map(e => e.dept))].length;
  document.getElementById('emp-total').textContent = total;
  document.getElementById('emp-salary-total').textContent = fmt(totalSalary);
  document.getElementById('emp-dept-count').textContent = depts;
  const grid = document.getElementById('emp-grid'), empty = document.getElementById('emp-empty');
  if (!emps.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  const colors = ['#22c55e', '#3b82f6', '#a855f7', '#f59e0b', '#ef4444', '#06b6d4', '#f97316'];
  grid.innerHTML = emps.map((e, i) => {
    const init = escHtml((e.fname[0] || '?') + (e.lname[0] || ''));
    const color = colors[i % colors.length];
    const years = e.start ? Math.floor((Date.now() - new Date(e.start)) / (365.25 * 24 * 3600 * 1000)) : 0;
    return `<div class="card emp-card">
      <div class="emp-av" style="background:linear-gradient(135deg,${color},${color}88)">${init}</div>
      <div style="flex:1;min-width:0">
        <div style="font-family:'Syne',sans-serif;font-size:15px;font-weight:700">${escHtml(e.fname)} ${escHtml(e.lname)}</div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px">${escHtml(e.pos) || '—'}</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
          <span class="dept-badge">${e.dept}</span>
          <span class="badge ${e.status === 'active' ? 'badge-green' : 'badge-gray'}">${e.status === 'active' ? '✓ Aktif' : 'Pasif'}</span>
          <span style="font-size:11px;color:var(--text-muted)">${years > 0 ? years + ' yıl' : e.start || ''}</span>
        </div>
        <div style="margin-top:8px;display:flex;justify-content:space-between;align-items:center">
          <span style="font-family:'Syne',sans-serif;font-weight:700;color:var(--green)">${fmt(e.salary || 0)}<span style="font-size:10px;font-family:'DM Sans',sans-serif;color:var(--text-muted)">/ay</span></span>
          <div class="action-btns"><button class="icon-btn edit" onclick="openEmpModal(${e.id})">✏️</button><button class="icon-btn del" onclick="deleteEmployee(${e.id})">🗑</button></div>
        </div>
      </div>
    </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════
//  DEBTS
// ══════════════════════════════════════════════════════════
let curDebtType = 'owe';
function setDebtType(t) { curDebtType = t; document.getElementById('dtype-owe').className = 'type-btn expense' + (t === 'owe' ? ' active' : ''); document.getElementById('dtype-lend').className = 'type-btn income' + (t === 'lend' ? ' active' : ''); }

function openDebtModal(type, id = null) {
  curDebtType = type;
  ['d-person', 'd-amount', 'd-desc', 'd-due'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('d-date').value = today(); document.getElementById('d-paid').value = '0';
  document.getElementById('d-id').value = id || '';
  document.getElementById('debt-modal-title').textContent = id ? 'Kaydı Düzenle' : 'Borç Ekle';
  if (id) { const db = (D().debts || []).find(x => x.id === id); if (!db) return; curDebtType = db.dtype; document.getElementById('d-person').value = db.person; document.getElementById('d-amount').value = db.amount; document.getElementById('d-desc').value = db.desc || ''; document.getElementById('d-date').value = db.date; document.getElementById('d-due').value = db.due || ''; document.getElementById('d-paid').value = db.paid || 0; }
  setDebtType(curDebtType);
  document.getElementById('debt-modal').classList.add('open');
}

function saveDebt() {
  const person = document.getElementById('d-person').value.trim();
  const rawAmt = parseFloat(document.getElementById('d-amount').value);
  const rawPaid = parseFloat(document.getElementById('d-paid').value);
  const amount = Math.round((isNaN(rawAmt) ? 0 : rawAmt) * 100) / 100;
  const paid = Math.round((isNaN(rawPaid) ? 0 : rawPaid) * 100) / 100;
  if (!person) { toast('Kişi adı zorunludur', 'error'); return; }
  if (!amount || amount <= 0) { toast('Tutar zorunludur', 'error'); return; }
  const maxDebt = isSirket() ? 99_999_999 : 999_999;
  if (amount > maxDebt) { toast('Maksimum tutar: ' + fmt(maxDebt), 'error'); return; }
  const d = D(); const eid = document.getElementById('d-id').value;
  if (!document.getElementById('d-date').value) { toast('Başlangıç tarihi zorunludur', 'error'); return; }
  const obj = { id: eid ? Number(eid) : uid(), dtype: curDebtType, person, amount, paid: Math.min(paid, amount), desc: document.getElementById('d-desc').value.trim(), date: document.getElementById('d-date').value, due: document.getElementById('d-due').value, status: paid >= amount ? 'paid' : 'active' };
  if (eid) { d.debts[d.debts.findIndex(x => x.id === Number(eid))] = obj; addLog('edit', 'debt', 'Borç düzenlendi: ' + person, fmt(amount)); toast('Güncellendi ✓'); }
  else { d.debts.push(obj); addLog('add', 'debt', (curDebtType === 'owe' ? 'Borç' : 'Alacak') + ' eklendi: ' + person, fmt(amount)); toast('Eklendi ✓'); }
  saveD(); closeModal('debt-modal'); renderDebts(); updateBadges(); if (curPage === 'dashboard') renderDash();
}

async function deleteDebt(id) {
  const ok = await confirmD('Bu kaydı silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const db = d.debts.find(x => x.id === id);
  addLog('delete', 'debt', 'Borç silindi: ' + (db ? db.person : '?'), '');
  d.debts = d.debts.filter(x => x.id !== id); saveD(); renderDebts(); updateBadges(); if (curPage === 'dashboard') renderDash(); toast('Silindi');
}

function markPaid(id) {
  const d = D();
  const idx = d.debts.findIndex(x => x.id === id);
  if (idx < 0) { toast('Kayıt bulunamadı', 'error'); return; }
  d.debts[idx].paid = d.debts[idx].amount;
  d.debts[idx].status = 'paid';
  addLog('pay', 'debt', 'Borç ödendi: ' + d.debts[idx].person, fmt(d.debts[idx].amount));
  saveD(); renderDebts(); updateBadges(); if (curPage === 'dashboard') renderDash(); toast('Ödendi ✓');
}
function openPayModal(id) {
  const db = D().debts.find(x => x.id === id);
  if (!db) return;
  document.getElementById('pay-id').value = id;
  document.getElementById('pay-amt').value = '';
  document.getElementById('pay-info').textContent = `${escHtml(db.person)} — Kalan: ${fmt(db.amount - (db.paid || 0))}`;
  document.getElementById('pay-modal').classList.add('open');
}
function savePayment() {
  const id = parseInt(document.getElementById('pay-id').value);
  const amt = parseFloat(document.getElementById('pay-amt').value);
  if (!amt || amt <= 0) { toast('Tutar zorunludur', 'error'); return; }
  const d = D();
  const idx = d.debts.findIndex(x => x.id === id);
  if (idx < 0) { toast('Kayıt bulunamadı', 'error'); return; }
  d.debts[idx].paid = Math.min(d.debts[idx].amount, (d.debts[idx].paid || 0) + amt);
  d.debts[idx].status = d.debts[idx].paid >= d.debts[idx].amount ? 'paid' : 'active';
  addLog('pay', 'debt', 'Ödeme: ' + d.debts[idx].person, fmt(amt));
  saveD(); closeModal('pay-modal'); renderDebts(); updateBadges(); if (curPage === 'dashboard') renderDash(); toast('Kaydedildi ✓');
}

function updateBadges() {
  const n = D().debts.filter(x => x.status === 'active').length;
  const b = document.getElementById('debt-badge'); if (b) { b.textContent = n; b.style.display = n ? 'inline' : 'none'; }
  if (isSirket()) { const invs = D().invoices || []; const n2 = invs.filter(i => i.status === 'pending' || i.status === 'overdue').length; const b2 = document.getElementById('inv-badge'); if (b2) { b2.textContent = n2; b2.style.display = n2 ? 'inline' : 'none'; } }
}

function renderDebts() {
  const search = document.getElementById('debt-search').value.toLowerCase();
  const tf = document.getElementById('debt-type-f').value, sf = document.getElementById('debt-status-f').value;
  const isSC = isSirket();
  document.getElementById('debts-page-title').textContent = isSC ? 'Cari Hesaplar' : 'Borçlar';
  const d = D(); let data = [...d.debts].sort((a, b) => b.id - a.id);
  if (search) data = data.filter(x => (x.person || '').toLowerCase().includes(search) || (x.desc || '').toLowerCase().includes(search));
  if (tf) data = data.filter(x => x.dtype === tf);
  if (sf) data = data.filter(x => x.status === sf);
  const actO = d.debts.filter(x => x.dtype === 'owe' && x.status === 'active');
  const actL = d.debts.filter(x => x.dtype === 'lend' && x.status === 'active');
  document.getElementById('d-owe-tot').textContent = fmt(actO.reduce((a, x) => a + (x.amount - (x.paid || 0)), 0));
  document.getElementById('d-owe-ct').textContent = actO.length + ' aktif';
  document.getElementById('d-lend-tot').textContent = fmt(actL.reduce((a, x) => a + (x.amount - (x.paid || 0)), 0));
  document.getElementById('d-lend-ct').textContent = actL.length + ' aktif';
  const net = actL.reduce((a, x) => a + (x.amount - (x.paid || 0)), 0) - actO.reduce((a, x) => a + (x.amount - (x.paid || 0)), 0);
  const ne = document.getElementById('d-net'); ne.textContent = fmt(net); ne.style.color = net >= 0 ? 'var(--green)' : 'var(--red)';
  const grid = document.getElementById('debts-grid'), empty = document.getElementById('debts-empty');
  if (!data.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  const nowMs = Date.now();
  grid.innerHTML = data.map(db => {
    const rem = db.amount - (db.paid || 0), pct = Math.min(100, Math.round(((db.paid || 0) / db.amount) * 100));
    const isOwe = db.dtype === 'owe', isPaid = db.status === 'paid';
    const isOver = db.due && !isPaid && new Date(db.due).getTime() < nowMs;
    const accent = isOwe ? 'var(--red)' : 'var(--green)';
    return `<div class="card goal-card ${isPaid ? 'debt-faded' : ''}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="display:flex;gap:5px;flex-wrap:wrap">
          <span class="badge ${isOwe ? 'badge-red' : 'badge-green'}">${isOwe ? '🔴 Borcum' : '🟢 Alacağım'}</span>
          ${isPaid ? '<span class="badge badge-gray">✓ Ödendi</span>' : ''}
          ${(isOver && d.settings.debtAlert) ? '<span class="badge badge-yellow">⚠️ Vade Geçti</span>' : ''}
        </div>
        <div class="action-btns">
          ${!isPaid ? `<button class="icon-btn pay" onclick="openPayModal(${db.id})" title="Ödeme">💳</button>` : ''}
          ${!isPaid ? `<button class="icon-btn check" onclick="markPaid(${db.id})" title="Ödendi">✓</button>` : ''}
          <button class="icon-btn edit" onclick="openDebtModal('${db.dtype}',${db.id})">✏️</button>
          <button class="icon-btn del" onclick="deleteDebt(${db.id})">🗑</button>
        </div>
      </div>
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;margin-bottom:3px">${escHtml(db.person)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${escHtml(db.desc) || ''}</div>
      <div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:12px">
        <span>Ödenen: <strong style="color:var(--green)">${fmt(db.paid || 0)}</strong></span>
        <span style="font-family:'Syne',sans-serif;font-size:15px;font-weight:800;color:${accent}">${fmt(db.amount)}</span>
      </div>
      <div class="progress-bar"><div class="${isOwe ? 'progress-fill-red' : 'progress-fill'}" style="width:${pct}%"></div></div>
      <div style="display:flex;justify-content:space-between;margin-top:7px;font-size:11px;color:var(--text-muted)">
        <span>${db.due ? `📅 ${escHtml(new Date(db.due).toLocaleDateString('tr-TR'))}${isOver ? ' ⚠️' : ''}` : ''}</span>
        <span style="color:${accent};font-weight:600">${isPaid ? 'Tamamlandı' : 'Kalan: ' + fmt(rem)} · %${pct}</span>
      </div></div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════
//  ANALYTICS CHARTS
// ══════════════════════════════════════════════════════════
function renderCharts() {
  const d = D();
  const txns = d.txns || [];
  const now = new Date();

  // —— 1. AYLIK GİRİŞ / ÇIKIŞ BAR (6 Ay) ——
  const monthLabels = [], monthIn = [], monthOut = [];
  for (let i = 5; i >= 0; i--) {
    const d2 = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const m = d2.getMonth(), y = d2.getFullYear();
    const mt = txns.filter(t => { const dd = new Date(t.date); return dd.getMonth() === m && dd.getFullYear() === y; });
    monthLabels.push(d2.toLocaleDateString('tr-TR', { month: 'short', year: '2-digit' }));
    monthIn.push(mt.filter(t => t.type === 'income').reduce((a, t) => a + t.amount, 0));
    monthOut.push(mt.filter(t => t.type === 'expense').reduce((a, t) => a + t.amount, 0));
  }
  if (charts.monthly) {
    charts.monthly.data.labels = monthLabels;
    charts.monthly.data.datasets[0].data = monthIn;
    charts.monthly.data.datasets[1].data = monthOut;
    charts.monthly.update();
  } else {
    charts.monthly = new Chart(document.getElementById('monthlyChart'), {
      type: 'bar',
      data: {
        labels: monthLabels,
        datasets: [
          { label: 'Giriş', data: monthIn, backgroundColor: 'rgba(34,197,94,.7)', borderRadius: 5, borderSkipped: false },
          { label: 'Çıkış', data: monthOut, backgroundColor: 'rgba(239,68,68,.7)', borderRadius: 5, borderSkipped: false }
        ]
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#64748b' } },
          y: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#64748b', callback: v => cur() + v.toLocaleString('tr-TR') } }
        }
      }
    });
  }

  // —— 2. KATEGORİ DAĞILIMI DOUGHNUT (Bu Ay — Tüm İşlemler) ——
  const curM = now.getMonth(), curY = now.getFullYear();
  const monthTxns = txns.filter(t => {
    const dd = new Date(t.date);
    return dd.getMonth() === curM && dd.getFullYear() === curY;
  });

  // Build a unified map: { category: { income: n, expense: n, total: n } }
  const catMapFull = {};
  monthTxns.forEach(t => {
    if (!catMapFull[t.cat]) catMapFull[t.cat] = { income: 0, expense: 0, total: 0 };
    catMapFull[t.cat][t.type] += t.amount;
    catMapFull[t.cat].total += t.amount;
  });

  const catLabels = Object.keys(catMapFull);
  const catData = catLabels.map(k => catMapFull[k].total);

  // Colour: mostly-income categories get green tones, mostly-expense get warm tones
  const incomeColors = ['#22c55e', '#4ade80', '#16a34a', '#86efac', '#14b8a6', '#06b6d4'];
  const expenseColors = ['#ef4444', '#f59e0b', '#a855f7', '#3b82f6', '#f97316', '#ec4899', '#84cc16', '#f43f5e'];
  const catColors = catLabels.map((k, i) => {
    const e = catMapFull[k];
    return e.income >= e.expense
      ? incomeColors[i % incomeColors.length]
      : expenseColors[i % expenseColors.length];
  });

  const catCtx = document.getElementById('categoryChart');
  if (!catCtx) return;

  if (charts.category) {
    if (catLabels.length === 0) {
      charts.category.data.labels = ['Veri Yok'];
      charts.category.data.datasets[0].data = [1];
      charts.category.data.datasets[0].backgroundColor = ['rgba(255,255,255,.08)'];
      charts.category.update();
    } else {
      charts.category.data.labels = catLabels;
      charts.category.data.datasets[0].data = catData;
      charts.category.data.datasets[0].backgroundColor = catColors;
      charts.category.update();
    }
  } else {
    if (catLabels.length === 0) {
      charts.category = new Chart(catCtx, {
        type: 'doughnut',
        data: {
          labels: ['Veri Yok'],
          datasets: [{ data: [1], backgroundColor: ['rgba(255,255,255,.08)'] }]
        },
        options: {
          responsive: true,
          plugins: { legend: { labels: { color: '#64748b' } } }
        }
      });
    } else {
      charts.category = new Chart(catCtx, {
        type: 'doughnut',
        data: {
          labels: catLabels,
          datasets: [{
            data: catData,
            backgroundColor: catColors,
            borderWidth: 2,
            borderColor: '#0a1628',
            hoverOffset: 10
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: '#94a3b8', font: { size: 11 }, padding: 10, boxWidth: 12 }
            },
            tooltip: {
              callbacks: {
                label: ctx2 => {
                  const k = ctx2.label;
                  const e = catMapFull[k];
                  const lines = [k + ': ' + cur() + Number(ctx2.raw).toLocaleString('tr-TR', { minimumFractionDigits: 2 })];
                  if (e.income > 0) lines.push('  ↑ Giriş: ' + cur() + e.income.toLocaleString('tr-TR', { minimumFractionDigits: 2 }));
                  if (e.expense > 0) lines.push('  ↓ Çıkış: ' + cur() + e.expense.toLocaleString('tr-TR', { minimumFractionDigits: 2 }));
                  return lines;
                }
              }
            }
          }
        }
      });
    }
  }


  // —— 3. GÜNLÜK NET HAREKET LİNE (Bu Ay) ——
  const daysInMonth = new Date(curY, curM + 1, 0).getDate();
  const dayLabels = [], dayNet = [];
  let runningTotal = 0;
  for (let day = 1; day <= daysInMonth; day++) {
    const dateStr = `${curY}-${String(curM + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    const dt = txns.filter(t => t.date === dateStr);
    const inc = dt.filter(t => t.type === 'income').reduce((a, t) => a + t.amount, 0);
    const exp = dt.filter(t => t.type === 'expense').reduce((a, t) => a + t.amount, 0);
    runningTotal += (inc - exp);
    dayLabels.push(day);
    dayNet.push(Math.round(runningTotal * 100) / 100);
  }
  if (charts.daily) {
    charts.daily.data.labels = dayLabels;
    charts.daily.data.datasets[0].data = dayNet;
    charts.daily.update();
  } else {
    charts.daily = new Chart(document.getElementById('dailyChart'), {
      type: 'line',
      data: {
        labels: dayLabels,
        datasets: [{
          label: 'Kümülatif Net',
          data: dayNet,
          borderColor: '#22c55e',
          backgroundColor: 'rgba(34,197,94,.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          pointBackgroundColor: '#22c55e',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#64748b', maxTicksLimit: 10 } },
          y: { grid: { color: 'rgba(255,255,255,.04)' }, ticks: { color: '#64748b', callback: v => cur() + v.toLocaleString('tr-TR') } }
        }
      }
    });
  }
}

// Duplicate getGoalSuggestions removed — canonical version kept below (line ~1298).

// Suggestion data is stored in a module-level map; only index is passed via onclick.
let _suggMap = [];
function openGoalFromSugg(idx) {
  const s = _suggMap[idx];
  if (!s) return;
  openGoalModal();
  setTimeout(() => {
    document.getElementById('g-name').value = s.title;
    // Strip HTML tags from desc before setting as plain text
    const tmp = document.createElement('div');
    tmp.innerHTML = s.desc;
    document.getElementById('g-desc').value = tmp.textContent || tmp.innerText || '';
    document.getElementById('g-target').value = s.target;
  }, 50);
}

function renderGoals() {
  const goals = D().goals;
  const grid = document.getElementById('goals-grid');
  const empty = document.getElementById('goals-empty');
  const suggs = getGoalSuggestions();
  _suggMap = suggs; // Store in module-level map, pass only index via onclick
  let suggEl = document.getElementById('goals-suggestions');
  if (!suggEl) { suggEl = document.createElement('div'); suggEl.id = 'goals-suggestions'; grid.parentNode.insertBefore(suggEl, grid); }
  suggEl.innerHTML = suggs.length ? `<div style="margin-bottom:20px">
    <div style="font-family:'Syne',sans-serif;font-size:14px;font-weight:700;margin-bottom:12px;color:var(--text-dim)">💡 Sisteme Göre Öneriler</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      ${suggs.map((s, si) => `<div style="flex:1;min-width:220px;background:rgba(34,197,94,.06);border:1px solid rgba(34,197,94,.15);border-radius:12px;padding:14px 16px;cursor:pointer"
          onclick="openGoalFromSugg(${si})"
          onmouseenter="this.style.background='rgba(34,197,94,.1)'" onmouseleave="this.style.background='rgba(34,197,94,.06)'">
        <div style="font-size:20px;margin-bottom:6px">${escHtml(s.icon)}</div>
        <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;margin-bottom:4px">${escHtml(s.title)}</div>
        <div style="font-size:11px;color:var(--text-muted);line-height:1.4;margin-bottom:8px">${escHtml(s.desc)}</div>
        <div style="font-size:12px;color:var(--green);font-weight:600">+ Hedef Oluştur</div>
      </div>`).join('')}
    </div></div>`: '';
  if (!goals.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  grid.innerHTML = goals.map(g => {
    const pct = Math.min(100, Math.round(((g.current || 0) / g.target) * 100));
    const cleanImg = escHtml(g.img);
    const imgH = g.img ? `<div class="goal-img"><img src="${cleanImg}" onerror="this.parentElement.innerHTML='🎯'"></div>` : `<div class="goal-img">🎯</div>`;
    return `<div class="card goal-card" onclick="openGoalDetail(${g.id})" style="cursor:pointer">
      ${imgH}
      <div style="display:flex;align-items:start;justify-content:space-between">
        <div class="goal-name">${escHtml(g.name)}</div>
        <div style="display:flex;gap:5px" onclick="event.stopPropagation()">
          <button class="icon-btn edit" onclick="openGoalModal(${g.id})">✏️</button>
          <button class="icon-btn del" onclick="deleteGoal(${g.id},event)">🗑</button>
        </div>
      </div>
      <div class="goal-desc">${escHtml(g.desc) || ''}</div>
      <div style="display:flex;justify-content:space-between;margin-bottom:7px;font-size:12px">
        <span style="color:var(--text-dim)">Birikim: <strong style="color:var(--green)">${fmt(g.current || 0)}</strong></span>
        <span style="font-weight:600">Hedef: ${fmt(g.target)}</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>
      <div style="display:flex;justify-content:space-between;margin-top:7px;font-size:11px">
        <span style="color:var(--text-muted)">${g.deadline ? '📅 ' + new Date(g.deadline).toLocaleDateString('tr-TR') : ''}</span>
        <span style="color:var(--green);font-weight:700">%${pct}</span>
      </div>
    </div>`;
  }).join('');
}

function openGoalDetail(id) {
  const g = D().goals.find(x => x.id === id);
  if (!g) return;
  const d = D();
  const pct = Math.min(100, Math.round(((g.current || 0) / g.target) * 100));
  const remaining = Math.max(0, g.target - (g.current || 0));
  const now = new Date();
  const m = now.getMonth(), y = now.getFullYear();
  const monT = (d.txns || []).filter(t => { const dd = new Date(t.date); return dd.getMonth() === m && dd.getFullYear() === y; });
  const monIn = monT.filter(t => t.type === 'income').reduce((a, t) => a + t.amount, 0);
  const monOut = monT.filter(t => t.type === 'expense').reduce((a, t) => a + t.amount, 0);
  const monthlySavings = Math.max(0, monIn - monOut);
  let daysLeft = null, deadlineStr = '';
  if (g.deadline) {
    const dl = new Date(g.deadline);
    daysLeft = Math.max(0, Math.ceil((dl - now) / 86400000));
    deadlineStr = dl.toLocaleDateString('tr-TR', { day: 'numeric', month: 'long', year: 'numeric' });
  }
  const tips = [];
  if (remaining > 0) {
    tips.push({ icon: '📅', title: 'Günlük Birikim', desc: `Her gün <strong>${fmt(+(remaining / 30).toFixed(2))}</strong> biriktirirseniz <strong>30 günde</strong> hedefinize ulaşırsınız.` });
    tips.push({ icon: '📆', title: 'Haftalık Birikim', desc: `Her hafta <strong>${fmt(+(remaining / 4.3).toFixed(2))}</strong> ayırırsanız hedefinize <strong>~1 ayda</strong> ulaşırsınız.` });
    if (daysLeft !== null && daysLeft > 0) {
      tips.push({ icon: '🎯', title: 'Vadeye Göre Plan', desc: `Hedefe <strong>${daysLeft} gün</strong> var. Günlük <strong>${fmt(+(remaining / daysLeft).toFixed(2))}</strong> veya haftalık <strong>${fmt(+(remaining / Math.max(1, daysLeft / 7)).toFixed(2))}</strong> biriktirin.` });
    }
    if (monthlySavings > 0) {
      const monthsNeeded = Math.ceil(remaining / monthlySavings);
      tips.push({ icon: '💡', title: 'Mevcut Tasarrufla', desc: `Aylık tasarrufunuz (<strong>${fmt(monthlySavings)}</strong>) ile hedefinize <strong>${monthsNeeded} ayda</strong> ulaşabilirsiniz.` });
    } else {
      tips.push({ icon: '⚠️', title: 'Tasarruf Yapın', desc: 'Bu ay geliriniz giderinizi karşılamıyor. Harcamalarınızı azaltarak tasarrufa başlayın.' });
    }
    if (monOut > 0) {
      const catMap = {};
      monT.filter(t => t.type === 'expense').forEach(t => { catMap[t.cat] = (catMap[t.cat] || 0) + t.amount; });
      const topCat = Object.entries(catMap).sort((a, b) => b[1] - a[1])[0];
      if (topCat) {
        const cutPct = Math.min(30, Math.round((remaining / topCat[1]) * 100));
        tips.push({ icon: '✂️', title: 'Harcama Kesme', desc: `En yüksek gider: <strong>${topCat[0]}</strong> (${fmt(topCat[1])}). Bu kategoride <strong>%${cutPct}</strong> tasarruf yaparak hedefinize yaklaşabilirsiniz.` });
      }
    }
  } else {
    tips.push({ icon: '🎉', title: 'Tebrikler!', desc: 'Hedefinize ulaştınız! Yeni bir hedef belirleyerek finansal büyümenize devam edebilirsiniz.' });
  }
  document.getElementById('gd-title').textContent = g.name;
  document.getElementById('gd-body').innerHTML = `
        <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:20px;margin-bottom:18px">
          ${g.desc ? `<div style="font-size:13px;color:var(--text-muted);margin-bottom:14px;line-height:1.5">${escHtml(g.desc)}</div>` : ''}
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
            <div style="text-align:center"><div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Birikim</div><div style="font-size:18px;font-weight:800;color:var(--green);font-family:'Syne',sans-serif">${fmt(g.current || 0)}</div></div>
            <div style="text-align:center"><div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Hedef</div><div style="font-size:18px;font-weight:800;font-family:'Syne',sans-serif">${fmt(g.target)}</div></div>
            <div style="text-align:center"><div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">Kalan</div><div style="font-size:18px;font-weight:800;color:var(--red);font-family:'Syne',sans-serif">${fmt(remaining)}</div></div>
          </div>
          <div class="progress-bar" style="height:10px;border-radius:6px"><div class="progress-fill" style="width:${pct}%;height:10px;border-radius:6px"></div></div>
          <div style="display:flex;justify-content:space-between;margin-top:8px;font-size:12px">
            <span style="color:var(--text-muted)">${deadlineStr ? '📅 ' + deadlineStr : 'Vade belirtilmedi'}</span>
            <span style="color:var(--green);font-weight:800;font-size:14px">%${pct}</span>
          </div>
        </div>
        <div style="font-family:'Syne',sans-serif;font-size:14px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px">🚀 Hedefe Nasıl Ulaşırsınız?</div>
        <div style="display:flex;flex-direction:column;gap:10px">
          ${tips.map(t => `<div style="display:flex;gap:12px;align-items:flex-start;padding:14px 16px;background:rgba(34,197,94,.04);border:1px solid rgba(34,197,94,.1);border-radius:12px">
            <div style="font-size:22px;flex-shrink:0;margin-top:2px">${t.icon}</div>
            <div><div style="font-weight:700;font-size:13px;margin-bottom:4px">${t.title}</div><div style="font-size:12px;color:var(--text-muted);line-height:1.6">${t.desc}</div></div>
          </div>`).join('')}
        </div>
        <div style="display:flex;gap:8px;margin-top:18px">
          <button class="btn btn-green" onclick="closeModal('goal-detail-modal');openGoalModal(${g.id})" style="flex:1">✏️ Düzenle</button>
          <button class="btn btn-ghost" onclick="closeModal('goal-detail-modal')" style="flex:1">Kapat</button>
        </div>`;
  document.getElementById('goal-detail-modal').classList.add('open');
}

// ══════════════════════════════════════════════════════════

//  GOALS
// ══════════════════════════════════════════════════════════
function useBalanceForGoal() { document.getElementById('g-current').value = Math.max(0, bal()).toFixed(2); toast('Bakiye alındı', 'info'); }
function openGoalModal(id = null) {
  ['g-name', 'g-desc', 'g-img', 'g-deadline'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('g-target').value = ''; document.getElementById('g-current').value = '0'; document.getElementById('g-id').value = '';
  document.getElementById('goal-modal-title').textContent = id ? 'Hedef Düzenle' : 'Yeni Hedef';
  if (id) { const g = D().goals.find(x => x.id === id); if (!g) return; document.getElementById('g-name').value = g.name; document.getElementById('g-desc').value = g.desc || ''; document.getElementById('g-img').value = g.img || ''; document.getElementById('g-target').value = g.target; document.getElementById('g-current').value = g.current || 0; document.getElementById('g-deadline').value = g.deadline || ''; document.getElementById('g-id').value = id; }
  document.getElementById('goal-modal').classList.add('open');
}
function saveGoal() {
  if (!requireWrite()) return;
  const name = document.getElementById('g-name').value.trim();
  const rawTarget = parseFloat(document.getElementById('g-target').value);
  const target = Math.round((isNaN(rawTarget) ? 0 : rawTarget) * 100) / 100;
  if (!name) { toast('Ad zorunludur', 'error'); return; } if (!target || target <= 0) { toast('Tutar zorunludur', 'error'); return; }
  const d = D(); const eid = document.getElementById('g-id').value;
  const rawCurrent = parseFloat(document.getElementById('g-current').value);
  const current = Math.round((isNaN(rawCurrent) ? 0 : rawCurrent) * 100) / 100;
  // Preserve original createdAt when editing; only set it on create
  const existingGoal = eid ? d.goals.find(x => x.id === Number(eid)) : null;
  const obj = { id: existingGoal ? existingGoal.id : uid(), name, target, current, desc: document.getElementById('g-desc').value, img: document.getElementById('g-img').value, deadline: document.getElementById('g-deadline').value, createdAt: existingGoal ? existingGoal.createdAt : new Date().toISOString() };
  if (eid) { d.goals[d.goals.findIndex(x => x.id === Number(eid))] = obj; addLog('edit', 'goal', 'Hedef düzenlendi: ' + name, ''); toast('Güncellendi ✓'); }
  else { d.goals.push(obj); addLog('add', 'goal', 'Hedef oluşturuldu: ' + name, fmt(target)); toast('Oluşturuldu ✓'); }
  saveD(); closeModal('goal-modal'); renderGoals();
}
async function deleteGoal(id, e) { if (e) e.stopPropagation(); if (!requireWrite()) return; const ok = await confirmD('Bu hedefi silmek istiyor musunuz?'); if (!ok) return; const d = D(); const g = d.goals.find(x => x.id === id); addLog('delete', 'goal', 'Hedef silindi: ' + (g ? g.name : '?'), ''); d.goals = d.goals.filter(x => x.id !== id); saveD(); renderGoals(); toast('Silindi'); }



// ══════════════════════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════════════════════
function renderSettings() {
  const d = D(); const s = d.settings;
  document.getElementById('set-fullname-disp').textContent = SESSION.fullname || SESSION.username;
  document.getElementById('set-user-disp').textContent = '@' + SESSION.username;
  document.getElementById('set-fullname').value = SESSION.fullname || '';
  const isSC = isSirket();
  document.getElementById('set-company-section').style.display = isSC ? 'block' : 'none';
  if (isSC) { document.getElementById('set-company').value = SESSION.company || ''; document.getElementById('set-sector').value = SESSION.sector || 'Ticaret'; document.getElementById('set-taxno').value = SESSION.taxNo || ''; }
  // Takım kartı — sadece şirket ve hesap sahibi için
  const teamCard = document.getElementById('set-team-card');
  if (teamCard) { teamCard.style.display = (isSC && !SESSION.isTeamMember) ? 'block' : 'none'; }
  if (isSC && !SESSION.isTeamMember) renderTeamList();
  updateAvDisplay();
  ['reminder', 'debtAlert', 'confirmDelete'].forEach(k => { const el = document.getElementById('tog-' + k); if (el) el.className = 'toggle' + (s[k] !== false ? ' on' : ''); });
  document.getElementById('set-currency').value = s.currency || '₺';
  const sw = s.sidebarWidth || 264; document.getElementById('sb-width-r').value = sw; document.getElementById('sb-width-v').textContent = sw + 'px';
  document.getElementById('set-txn-c').textContent = d.txns.length; document.getElementById('set-debt-c').textContent = d.debts.length; document.getElementById('set-goal-c').textContent = d.goals.length; document.getElementById('set-log-c').textContent = d.logs.length;
  // Render device sessions
  renderDeviceSessions();
}



function updateAvDisplay() {
  const avBig = document.getElementById('set-av'), avSmall = document.getElementById('sidebar-av');
  const init = (SESSION.fullname || SESSION.username || '?').charAt(0).toUpperCase();
  if (SESSION.avatar) { avBig.innerHTML = `<img src="${SESSION.avatar}"><input type="file" id="av-file" accept="image/*" style="display:none" onchange="handleAvatar(this)">`; avSmall.innerHTML = `<img src="${SESSION.avatar}">`; }
  else { avBig.innerHTML = `${init}<input type="file" id="av-file" accept="image/*" style="display:none" onchange="handleAvatar(this)">`; avSmall.innerHTML = init; }
}

function handleAvatar(input) {
  const f = input.files[0];
  if (!f) return;
  // Guard: reject files over 500 KB to prevent localStorage quota exhaustion
  if (f.size > 512 * 1024) { toast('Fotoğraf çok büyük (max 500 KB)', 'error'); input.value = ''; return; }
  const r = new FileReader();
  r.onload = e => {
    SESSION.avatar = e.target.result;
    const users = getUsers();
    const idx = users.findIndex(x => x.uid === SESSION.uid);
    if (idx > -1) { users[idx].avatar = e.target.result; saveUsers(users); }
    sessionStorage.setItem('kt_sess', JSON.stringify(SESSION));
    updateAvDisplay();
    toast('Fotoğraf güncellendi ✓');
  };
  r.readAsDataURL(f);
}

function saveProfile() {
  const fullname = document.getElementById('set-fullname').value.trim(); if (!fullname) { toast('Ad soyad zorunludur', 'error'); return; }
  SESSION.fullname = fullname;
  const users = getUsers(); const idx = users.findIndex(x => x.uid === SESSION.uid);
  if (idx > -1) { users[idx].fullname = fullname; if (isSirket()) { const c = document.getElementById('set-company').value.trim(); const sc = document.getElementById('set-sector').value; const tn = document.getElementById('set-taxno').value.trim(); users[idx].company = c; users[idx].sector = sc; users[idx].taxNo = tn; SESSION.company = c; SESSION.sector = sc; SESSION.taxNo = tn; } saveUsers(users); }
  sessionStorage.setItem('kt_sess', JSON.stringify(SESSION));
  document.getElementById('sidebar-uname').textContent = fullname;
  document.getElementById('sidebar-utype').textContent = isSirket() ? '🏢 ' + (SESSION.company || 'Şirket') : '👤 Bireysel';
  renderSettings(); addLog('edit', 'auth', 'Profil güncellendi', fullname); toast('Profil kaydedildi ✓');
}

async function changePassword() {
  const old = document.getElementById('cp-old').value;
  const n1 = document.getElementById('cp-n1').value;
  const n2 = document.getElementById('cp-n2').value;
  if (!old) { toast('Mevcut şifreyi girin', 'error'); return; }
  if (n1.length < 6) { toast('Yeni şifre en az 6 karakter', 'error'); return; }
  if (n1 !== n2) { toast('Şifreler eşleşmiyor', 'error'); return; }
  const users = getUsers();
  const idx = users.findIndex(x => x.uid === SESSION.uid);
  if (idx < 0) { toast('Mevcut şifre hatalı', 'error'); return; }
  const storedPw = users[idx].password;
  let oldMatch = false;
  if (storedPw && storedPw.startsWith('sha256:')) {
    oldMatch = storedPw === await hashPwAsync(old);
  } else {
    oldMatch = storedPw === hashPwLegacy(old);
  }
  if (!oldMatch) { toast('Mevcut şifre hatalı', 'error'); return; }
  users[idx].password = await hashPwAsync(n1);
  saveUsers(users);
  ['cp-old', 'cp-n1', 'cp-n2'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('cp-pw-fill').style.width = '0%';
  addLog('system', 'auth', 'Şifre değiştirildi', '');
  toast('Şifre güncellendi ✓');
}

function toggleSetting(el, key) { el.classList.toggle('on'); D().settings[key] = el.classList.contains('on'); saveD(); if (key === 'lightTheme') applyTheme(); toast('Kaydedildi ✓', 'info'); }
function setCurrency(v) { D().settings.currency = v; saveD(); document.querySelectorAll('.cur-sym').forEach(el => el.textContent = v); toast('Para birimi: ' + v, 'info'); }
function setAccent(color, dim, el) { document.querySelectorAll('.swatch').forEach(s => s.classList.remove('on')); el.classList.add('on'); document.documentElement.style.setProperty('--green', color); document.documentElement.style.setProperty('--green-dim', dim); D().settings.accentColor = color; D().settings.accentDim = dim; saveD(); toast('Renk güncellendi ✓', 'info'); }
function setSidebarW(v) { document.documentElement.style.setProperty('--sidebar-w', v + 'px'); document.getElementById('sb-width-v').textContent = v + 'px'; D().settings.sidebarWidth = parseInt(v); saveD(); }
function applyAuthPhotoFile(input) {
  const f = input.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = e => {
    const url = e.target.result;
    D().settings.authPhoto = url; saveD();
    const img = document.getElementById('auth-bg-img');
    img.src = url; img.classList.add('on');
    const prev = document.getElementById('auth-photo-preview');
    if (prev) { prev.innerHTML = `<img src="${url}" style="width:100%;height:100%;object-fit:cover">`; }
    toast('Fotoğraf güncellendi ✓');
  };
  r.readAsDataURL(f);
}
function clearAuthPhoto() {
  D().settings.authPhoto = ''; saveD();
  const img = document.getElementById('auth-bg-img'); img.src = ''; img.classList.remove('on');
  const prev = document.getElementById('auth-photo-preview');
  if (prev) prev.innerHTML = '🖼️';
  toast('Kaldırıldı', 'info');
}
function handleGoalImg(input) {
  const f = input.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = e => {
    document.getElementById('g-img').value = e.target.result;
    const prev = document.getElementById('g-img-preview');
    if (prev) prev.innerHTML = `<img src="${e.target.result}" style="width:100%;height:100%;object-fit:cover;border-radius:8px">`;
  };
  r.readAsDataURL(f);
}
function clearGoalImg() {
  document.getElementById('g-img').value = '';
  document.getElementById('g-img-file').value = '';
  const prev = document.getElementById('g-img-preview');
  if (prev) prev.innerHTML = '🎯';
}

// ══════════════════════════════════════════════════════════
//  GOAL SUGGESTIONS (AI-free, rule-based)
// ══════════════════════════════════════════════════════════
function getGoalSuggestions() {
  const d = D();
  const b = bal();
  const goals = d.goals || [];
  const txns = d.txns || [];
  const now = new Date();
  const m = now.getMonth(), y = now.getFullYear();
  const monT = txns.filter(t => { const dd = new Date(t.date); return dd.getMonth() === m && dd.getFullYear() === y; });
  const monIn = monT.filter(t => t.type === 'income').reduce((a, t) => a + t.amount, 0);
  const monOut = monT.filter(t => t.type === 'expense').reduce((a, t) => a + t.amount, 0);
  const savingsRate = monIn > 0 ? ((monIn - monOut) / monIn * 100) : 0;
  const suggestions = [];
  // Tasarruf oranı düşükse
  if (savingsRate < 20 && monIn > 0) suggestions.push({ title: '💰 Tasarruf Fonu', desc: `Bu ay gelirinizin sadece %${savingsRate.toFixed(0)}’ini biriktiriyorsunuz. Hedef: %20`, target: Math.round(monIn * 0.2), icon: '💰' });
  // Acil fon yoksa
  const hasEmergency = goals.some(g => g.name.toLowerCase().includes('acil') || g.name.toLowerCase().includes('emergency'));
  if (!hasEmergency && monOut > 0) suggestions.push({ title: '🛡️ Acil Durum Fonu', desc: `3 aylık gidere eşdeğer (${fmt(monOut * 3)}) acil fon oluşturun.`, target: Math.round(monOut * 3), icon: '🛡️' });
  // Bakiye fazlaysa yatırım önerisi
  if (b > 5000 && goals.length < 3) suggestions.push({ title: '📈 Yatırım Birikimi', desc: `Mevcut bakiyeniz (${fmt(b)}) yatırım için uygun bir başlangıç.`, target: Math.round(b * 2), icon: '📈' });
  // Borcu çoksa borcu kapatma hedefi
  const debts = d.debts.filter(x => x.status === 'active' && x.dtype === 'owe');
  const totalDebt = debts.reduce((a, x) => a + (x.amount - (x.paid || 0)), 0);
  if (totalDebt > 0 && !goals.some(g => g.name.toLowerCase().includes('borç'))) suggestions.push({ title: '🔴 Borç Kapatma', desc: `Toplam borcunuz ${fmt(totalDebt)}. Hedef belirleyerek daha hızlı ödeyin.`, target: Math.round(totalDebt), icon: '🔴' });
  return suggestions;
}

// ══════════════════════════════════════════════════════════
//  SCREENSHOT PROTECTION
// ══════════════════════════════════════════════════════════
(function () {
  let ssTimer = null;
  function showSSBlock() {
    const el = document.getElementById('ss-overlay');
    if (el) { el.classList.add('on'); clearTimeout(ssTimer); ssTimer = setTimeout(() => el.classList.remove('on'), 3000); }
    toast('🚫 Ekran görüntüsü yasak!', 'error');
  }
  // PrintScreen key
  document.addEventListener('keyup', e => {
    if (e.key === 'PrintScreen' || e.keyCode === 44) { e.preventDefault(); showSSBlock(); }
  });
  // visibilitychange (bazı SS araçları için)
  document.addEventListener('keydown', e => {
    if (e.key === 'PrintScreen') { e.preventDefault(); showSSBlock(); return false; }
  });
  // Windows Snipping Tool pattern (Win+Shift+S)
  document.addEventListener('keydown', e => {
    if (e.shiftKey && e.metaKey && (e.key === 's' || e.key === 'S')) { e.preventDefault(); showSSBlock(); }
  });
})();

// ══════════════════════════════════════════════════════════
//  EXPORT / BACKUP / RESET
// ══════════════════════════════════════════════════════════
function exportCSV() { const t = D().txns; if (!t.length) { toast('İşlem yok', 'error'); return; } dlFile('islemler-' + today() + '.csv', 'text/csv', '\uFEFF' + [['Tarih', 'Tür', 'Kategori', 'Dept', 'KDV', 'Açıklama', 'Not', 'Tutar'], ...t.map(x => [x.date, x.type === 'income' ? 'Giriş' : 'Çıkış', x.cat, x.dept || '', x.kdv || 0, x.desc || '', x.note || '', x.amount])].map(r => r.map(v => `"${v}"`).join(',')).join('\n')); toast('CSV indirildi ✓'); }
function exportDebtsCSV() { const db = D().debts; if (!db.length) { toast('Borç yok', 'error'); return; } dlFile('borclar-' + today() + '.csv', 'text/csv', '\uFEFF' + [['Tür', 'Kişi', 'Tutar', 'Ödenen', 'Kalan', 'Açıklama', 'Başlangıç', 'Vade', 'Durum'], ...db.map(x => [x.dtype === 'owe' ? 'Borcum' : 'Alacağım', x.person, x.amount, x.paid || 0, x.amount - (x.paid || 0), x.desc || '', x.date, x.due || '', x.status === 'paid' ? 'Ödendi' : 'Aktif'])].map(r => r.map(v => `"${v}"`).join(',')).join('\n')); toast('CSV indirildi ✓'); }
function exportLogCSV() { const l = D().logs; if (!l.length) { toast('Log yok', 'error'); return; } dlFile('log-' + today() + '.csv', 'text/csv', '\uFEFF' + [['Tarih', 'Saat', 'Tür', 'Kategori', 'Mesaj', 'Detay'], ...l.map(x => { const d = new Date(x.ts); return [d.toLocaleDateString('tr-TR'), d.toLocaleTimeString('tr-TR'), x.type, x.cat, x.msg, x.detail || '']; })].map(r => r.map(v => `"${v}"`).join(',')).join('\n')); toast('Log CSV indirildi ✓'); }
function backupData() { const d = D(); dlFile('kasa-yedek-' + today() + '.json', 'application/json', JSON.stringify({ version: 5, date: new Date().toISOString(), ...d }, null, 2)); addLog('system', 'auth', 'Yedek alındı', ''); toast('Yedek alındı ✓'); }
function restoreBackup(input) {
  const f = input.files[0]; if (!f) return;
  const r = new FileReader();
  r.onload = async e => {
    try {
      const bk = JSON.parse(e.target.result);
      if (!bk.txns && !bk.debts) { toast('Geçersiz dosya', 'error'); return; }
      const ok = await showConfirm('Mevcut veriler yedek dosyasındakilerle değiştirilecek. Bu işlem geri alınamaz!', {
        title: '⚠️ Yedekten Geri Yükle',
        confirmText: 'Evet, Geri Yükle',
        danger: true
      });
      if (!ok) return;
      const d = D();
      d.txns = bk.txns || []; d.debts = bk.debts || []; d.goals = bk.goals || [];
      d.invoices = bk.invoices || []; d.employees = bk.employees || [];
      if (bk.logs) d.logs = [...d.logs, ...bk.logs.filter(l => !d.logs.some(x => x.id === l.id))];
      if (bk.settings) Object.assign(d.settings, bk.settings);
      saveD(); addLog('system', 'auth', 'Yedekten geri yüklendi', f.name);
      if (curPage === 'dashboard') renderDash(); renderSettings(); updateBadges(); toast('Yedek yüklendi ✓');
    } catch { toast('Dosya okunamadı', 'error'); }
  };
  r.readAsText(f); input.value = '';
}
async function resetTxns() {
  const ok = await showConfirm('Tüm işlem kayıtları kalıcı olarak silinecek. Bu işlem geri alınamaz!', {
    title: '🗑 İşlemleri Temizle',
    confirmText: 'Evet, Temizle',
    danger: true
  });
  if (!ok) return;
  const d = D(); addLog('system', 'auth', 'İşlemler temizlendi', d.txns.length + ' kayıt');
  d.txns = []; saveD(); if (curPage === 'dashboard') renderDash(); renderSettings(); toast('Temizlendi');
}
async function resetAll() {
  const ok1 = await showConfirm('TÜM veriler (işlemler, borçlar, hedefler, faturalar, çalışanlar) silinecek. Log korunur.', {
    title: '⚠️ Tüm Verileri Sıfırla',
    confirmText: 'Devam Et →',
    danger: true
  });
  if (!ok1) return;
  const ok2 = await showConfirm('Bu işlem GERİ ALINAMAZ! Emin misiniz?', {
    title: '🚨 Son Uyarı',
    confirmText: 'Evet, Her Şeyi Sil',
    danger: true
  });
  if (!ok2) return;
  const d = D(); addLog('system', 'auth', 'Tüm veriler sıfırlandı', `${d.txns.length}+${d.debts.length}+${d.goals.length} kayıt`);
  d.txns = []; d.debts = []; d.goals = []; d.invoices = []; d.employees = [];
  saveD(); if (curPage === 'dashboard') renderDash(); renderSettings(); updateBadges(); toast('Sıfırlandı (log korundu)');
}
function dlFile(name, type, content) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Revoke the object URL to free memory
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ══════════════════════════════════════════════════════════
//  MODALS
// ══════════════════════════════════════════════════════════
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
// Click-outside closes modals — EXCEPT onboarding, tutorial and invitation modals (user must use buttons)
const _NO_CLICK_OUTSIDE = new Set(['onboarding-modal', 'tutorial-modal', 'invitation-modal']);
document.querySelectorAll('.modal-overlay').forEach(m => m.addEventListener('click', e => {
  if (e.target === m && !_NO_CLICK_OUTSIDE.has(m.id)) m.classList.remove('open');
}));


// ══════════════════════════════════════════════════════════
//  INIT
// ══════════════════════════════════════════════════════════
function initApp() {
  const s = D().settings;
  applyTheme();
  if (!s.onboarded) {
    // Kısa gecikme: uygulama render olduktan sonra modal açılsın
    setTimeout(() => {
      document.getElementById('onboarding-modal').classList.add('open');
    }, 300);
  } else {
    // Check for pending invitations immediately after login
    checkPendingInvitations();
  }
  if (s.accentColor) document.documentElement.style.setProperty('--green', s.accentColor);
  if (s.accentDim) document.documentElement.style.setProperty('--green-dim', s.accentDim);
  if (s.sidebarWidth) document.documentElement.style.setProperty('--sidebar-w', s.sidebarWidth + 'px');
  if (s.authPhoto) { const img = document.getElementById('auth-bg-img'); img.src = s.authPhoto; img.classList.add('on'); }
  document.querySelectorAll('.cur-sym').forEach(el => el.textContent = s.currency || '₺');
  document.getElementById('sidebar-uname').textContent = SESSION.fullname || SESSION.username;
  document.getElementById('sidebar-utype').textContent = isSirket() ? '🏢 ' + (SESSION.company || 'Şirket') : '👤 Bireysel';
  document.getElementById('sidebar-mode-lbl').textContent = isSirket() ? 'Şirket Modu' : 'Bireysel Mod';
  updateAvDisplay();
  const n = new Date();
  document.getElementById('txn-month-f').value = `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}`;
  refreshCatFilter();
  renderNav();
  updateBadges();
  // Record this login session/device
  recordLoginSession();
  goPage('dashboard');
  // Start session watcher and idle timer AFTER login
  _startSessionWatcher();
  _startIdleTimer();
}

// ══════════════════════════════════════════════════════════
//  DEVICE / SESSION TRACKING
// ══════════════════════════════════════════════════════════
function getDeviceInfo() {
  const ua = navigator.userAgent;
  let device = '💻 Bilgisayar';
  let browser = 'Tarayıcı';
  if (/iPhone|iPad|iPod/i.test(ua)) device = '📱 iPhone/iPad';
  else if (/Android/i.test(ua)) device = '📱 Android';
  else if (/Mac/i.test(ua)) device = '💻 Mac';
  else if (/Windows/i.test(ua)) device = '💻 Windows';
  if (/Chrome/i.test(ua) && !/Chromium|Edge/i.test(ua)) browser = 'Chrome';
  else if (/Firefox/i.test(ua)) browser = 'Firefox';
  else if (/Safari/i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';
  else if (/Edge/i.test(ua)) browser = 'Edge';
  return { device, browser };
}

function recordLoginSession() {
  const d = D();
  if (!d.deviceSessions) d.deviceSessions = [];
  const { device, browser } = getDeviceInfo();
  const deviceKey = device + '|' + browser; // Cihaz kimliği: tür + tarayıcı

  // sessionId: bu oturuma özel token — sessionStorage'dan al veya yeni oluştur
  const sessionId = SESSION.sessionId || cryptoToken();
  SESSION.sessionId = sessionId;
  sessionStorage.setItem('kt_sess', JSON.stringify(SESSION));

  // Aynı cihazdan daha önce giriş yapılmış mı?
  const existing = d.deviceSessions.find(s => s.deviceKey === deviceKey);
  if (existing) {
    // Kaydı güncelle — yeni oturum aç, eski sessionId'yi değiştir
    existing.sessionId = sessionId;
    existing.lastLoginAt = new Date().toISOString();
    existing.isActive = true;
    existing.loginCount = (existing.loginCount || 1) + 1;
  } else {
    // Yeni cihaz — listeye ekle
    d.deviceSessions.push({
      sessionId,
      deviceKey,
      device,
      browser,
      firstLoginAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
      isActive: true,
      loginCount: 1
    });
    // Max 20 cihaz tut
    if (d.deviceSessions.length > 20) d.deviceSessions = d.deviceSessions.slice(-20);
  }
  saveD();
}

function renderDeviceSessions() {
  const el = document.getElementById('device-sessions-list');
  if (!el) return;
  const sessions = [...(D().deviceSessions || [])].reverse();
  if (!sessions.length) {
    el.innerHTML = `<div style="text-align:center;padding:20px;color:var(--text-muted);font-size:13px">Kayıtlı cihaz bulunmamaktadır</div>`;
    return;
  }

  const active = sessions.filter(s => s.isActive === true);
  const inactive = sessions.filter(s => s.isActive !== true);

  const _icon = s => s.device && s.device.includes('📱') ? '📱' : '💻';
  const _date = iso => iso ? new Date(iso).toLocaleDateString('tr-TR', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';

  let html = '';

  // ─── AKTİF CİHAZLAR ───────────────────────────────
  html += `<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--green);margin-bottom:10px">Aktif Oturumlar (${active.length})</div>`;
  if (!active.length) {
    html += `<div style="font-size:12px;color:var(--text-muted);margin-bottom:18px;padding:12px;background:rgba(255,255,255,.02);border-radius:8px">Aktif oturum yok.</div>`;
  } else {
    html += active.map(s => {
      const isCur = s.sessionId === SESSION.sessionId;
      return `<div style="display:flex;align-items:center;gap:12px;padding:12px 14px;background:${isCur ? 'rgba(34,197,94,.06)' : 'rgba(255,255,255,.03)'};border:1px solid ${isCur ? 'rgba(34,197,94,.2)' : 'rgba(255,255,255,.06)'};border-radius:10px;margin-bottom:8px">
        <div style="font-size:24px;flex-shrink:0">${_icon(s)}</div>
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;font-size:13px">${escHtml(s.device)} · ${escHtml(s.browser)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
            ${s.loginCount > 1 ? `${s.loginCount}. giriş · ` : ''}Son giriş: ${_date(s.lastLoginAt)}
          </div>
        </div>
        ${isCur
          ? '<span class="badge badge-green" style="font-size:10px;flex-shrink:0">● Bu Cihaz</span>'
          : `<button class="btn btn-ghost" style="font-size:11px;padding:5px 10px;color:var(--red);flex-shrink:0" onclick="terminateSession('${s.sessionId}')">⏏ Kapat</button>`}
      </div>`;
    }).join('');
  }

  // ─── TANINAN CİHAZLAR (GEÇMİŞ) ───────────────────
  if (inactive.length) {
    html += `<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin:18px 0 10px">Tanınan Cihazlar — Geçmiş (${inactive.length})</div>`;
    html += inactive.map(s => {
      return `<div style="display:flex;align-items:center;gap:12px;padding:12px 14px;background:rgba(255,255,255,.015);border:1px solid rgba(255,255,255,.04);border-radius:10px;margin-bottom:8px;opacity:.65">
        <div style="font-size:22px;flex-shrink:0;filter:grayscale(1)">${_icon(s)}</div>
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;font-size:13px;color:var(--text-muted)">${escHtml(s.device)} · ${escHtml(s.browser)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">
            ${s.loginCount ? `${s.loginCount} giriş · ` : ''}Son çıkış: ${_date(s.lastLogoutAt)}
          </div>
        </div>
        <span class="badge badge-gray" style="font-size:10px;flex-shrink:0">Oturum Kapalı</span>
      </div>`;
    }).join('');
  }

  el.innerHTML = html;
}

function terminateSession(sessionId) {
  const d = D();
  if (!d.deviceSessions) return;
  const target = d.deviceSessions.find(s => s.sessionId === sessionId);
  if (target) {
    target.isActive = false;
    target.lastLogoutAt = new Date().toISOString();
    saveD();
    renderDeviceSessions();
    toast(target.device + ' cihazının oturumu kapatıldı ✓', 'info');
  }
}

// ══════════════════════════════════════════════════════════
//  PENDING INVITATIONS CHECK
// ══════════════════════════════════════════════════════════
let _currentInvitation = null;
function checkPendingInvitations() {
  const d = D();
  const pending = (d.pendingInvitations || []).filter(x => x.status === 'pending');
  if (!pending.length) return;
  // Show first pending invitation
  _currentInvitation = pending[0];
  showInvitationModal(_currentInvitation);
}

function showInvitationModal(inv) {
  const pLabel = { admin: 'Tam Yetki (Admin)', editor: 'Düzenleyici', viewer: 'Salt Okunur (Görüntüleyici)' };
  document.getElementById('inv-modal-company-title').textContent = 'Ekip Daveti';
  document.getElementById('inv-modal-msg').textContent =
    `"${inv.fromCompany}" şirketi sizi kendi Kasaly hesabına "${pLabel[inv.role] || inv.role}" yetkisiyle eklemek istemektedir. Bu daveti kabul etmek istediğinizden emin misiniz?`;
  document.getElementById('inv-detail-company').textContent = inv.fromCompany;
  document.getElementById('inv-detail-role').textContent = pLabel[inv.role] || inv.role;
  document.getElementById('inv-detail-sender').textContent = '@' + inv.fromUsername;
  document.getElementById('invitation-modal').classList.add('open');
}

function respondInvitation(accepted) {
  document.getElementById('invitation-modal').classList.remove('open');
  if (!_currentInvitation) return;
  const inv = _currentInvitation;
  _currentInvitation = null;
  const d = D();
  if (!d.pendingInvitations) d.pendingInvitations = [];
  const pi = d.pendingInvitations.find(x => x.id === inv.id);
  if (pi) pi.status = accepted ? 'accepted' : 'rejected';
  saveD();
  if (accepted) {
    // Add to sender's teamAccess
    const senderData = getUserData(inv.fromUid);
    if (senderData) {
      if (!senderData.teamAccess) senderData.teamAccess = [];
      // Remove from pending invitations in sender's data
      if (senderData.teamInvitations) {
        const si = senderData.teamInvitations.find(x => x.id === inv.id);
        if (si) si.status = 'accepted';
      }
      // Update team member status if exists, else add
      const existingMember = senderData.teamAccess.find(x => x.username.toLowerCase() === SESSION.username.toLowerCase());
      if (!existingMember) {
        senderData.teamAccess.push({
          username: SESSION.username,
          fullname: SESSION.fullname || SESSION.username,
          role: inv.role,
          addedAt: new Date().toISOString()
        });
      }
      saveUserData(inv.fromUid, senderData);
    }
    toast(`"${inv.fromCompany}" ekibine katıldınız ✓`, 'ok');
    addLog('system', 'auth', 'Ekip daveti kabul edildi: ' + inv.fromCompany, inv.role);
  } else {
    toast('Davet reddedildi', 'info');
    addLog('system', 'auth', 'Ekip daveti reddedildi: ' + inv.fromCompany, '');
  }
  // Check if there are more pending invitations
  const remaining = (D().pendingInvitations || []).filter(x => x.status === 'pending');
  if (remaining.length) {
    setTimeout(() => { _currentInvitation = remaining[0]; showInvitationModal(remaining[0]); }, 600);
  }
}

// ══════════════════════════════════════════════════════════
//  TUTORIAL SYSTEM
// ══════════════════════════════════════════════════════════
const TUTORIAL_STEPS = [
  {
    title: 'Kasaly\'ye Hoş Geldiniz 👋',
    sub: 'Finansal kontrol sisteminize genel bakış',
    body: `<div style="text-align:center;margin-bottom:20px"><div style="font-size:56px">🏠</div></div>
      <p style="color:var(--text-muted);font-size:13px;line-height:1.8">Kasaly, bireysel ve kurumsal finansal işlemlerinizi tek bir platformda yönetmenizi sağlayan profesyonel bir kasa takip sistemidir.</p>
      <ul style="margin:16px 0;padding-left:20px;color:var(--text-muted);font-size:13px;line-height:2">
        <li>Gelir ve giderlerinizi kayıt altına alın</li>
        <li>Borç ve alacaklarınızı takip edin</li>
        <li>Finansal hedefler belirleyin</li>
        <li>Kapsamlı raporlar ve grafikler görüntüleyin</li>
      </ul>`
  },
  {
    title: 'Dashboard — Ana Panel',
    sub: 'Finansal durumunuza genel bakış',
    body: `<div style="text-align:center;margin-bottom:20px"><div style="font-size:56px">📊</div></div>
      <p style="color:var(--text-muted);font-size:13px;line-height:1.8">Dashboard sayfasında anlık kasa bakiyenizi, bugünkü ve bu ayki gelir/gider özetlerinizi görebilirsiniz.</p>
      <div style="background:var(--green-dim);border:1px solid rgba(34,197,94,.2);border-radius:10px;padding:14px;margin-top:14px;font-size:13px">
        💡 <strong>İpucu:</strong> Sol üstteki "+" İşlem butonuyla hızlıca gelir veya gider kaydı oluşturabilirsiniz.
      </div>`
  },
  {
    title: 'İşlemler — Kasa Hareketleri',
    sub: 'Gelir ve gider kayıtları',
    body: `<div style="text-align:center;margin-bottom:20px"><div style="font-size:56px">💸</div></div>
      <p style="color:var(--text-muted);font-size:13px;line-height:1.8">İşlemler sayfasında tüm gelir ve gider hareketlerinizi listeleyebilir, tarihe, kategoriye veya türe göre filtreleyebilirsiniz.</p>
      <div style="background:var(--blue-dim);border:1px solid rgba(59,130,246,.2);border-radius:10px;padding:14px;margin-top:14px;font-size:13px">
        📋 Kayıtlarınızı CSV formatında dışa aktarabilirsiniz.
      </div>`
  },
  {
    title: 'Borçlar — Cari Hesaplar',
    sub: 'Borç ve alacaklarınızı takip edin',
    body: `<div style="text-align:center;margin-bottom:20px"><div style="font-size:56px">🤝</div></div>
      <p style="color:var(--text-muted);font-size:13px;line-height:1.8">Borçlarım ve Alacaklarım bölümünde kişi veya firma bazlı borç takibi yapabilir, kısmi ödemeleri kaydedebilirsiniz.</p>
      <div style="background:var(--red-dim);border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:14px;margin-top:14px;font-size:13px">
        ⚠️ Vadesi geçen borçlar için otomatik uyarı sistemi bulunmaktadır.
      </div>`
  },
  {
    title: 'Analitik — Raporlar',
    sub: 'Finansal verilerinizin grafiksel özeti',
    body: `<div style="text-align:center;margin-bottom:20px"><div style="font-size:56px">📈</div></div>
      <p style="color:var(--text-muted);font-size:13px;line-height:1.8">Analitik sayfasında aylık gelir/gider karşılaştırmaları, kategori dağılım grafikleri ve günlük net hareket trendlerini görüntüleyebilirsiniz.</p>`
  },
  {
    title: 'Hedefler',
    sub: 'Finansal hedeflerinizi belirleyin',
    body: `<div style="text-align:center;margin-bottom:20px"><div style="font-size:56px">🎯</div></div>
      <p style="color:var(--text-muted);font-size:13px;line-height:1.8">Hedefler bölümünde tasarruf veya yatırım hedefleri oluşturabilir, ilerlemenizi takip edebilir ve sisteme özel önerileri inceleyebilirsiniz.</p>`
  },
  {
    title: 'Ayarlar — Kişiselleştirme',
    sub: 'Sistemi ihtiyaçlarınıza göre yapılandırın',
    body: `<div style="text-align:center;margin-bottom:20px"><div style="font-size:56px">⚙️</div></div>
      <p style="color:var(--text-muted);font-size:13px;line-height:1.8">Ayarlar sayfasında profil bilgilerinizi güncelleyebilir, görünüm tercihlerinizi değiştirebilir, verilerinizi yedekleyebilir ve aktif oturumlarınızı yönetebilirsiniz.</p>
      <div style="background:var(--green-dim);border:1px solid rgba(34,197,94,.2);border-radius:10px;padding:14px;margin-top:14px;font-size:13px">
        ✅ Tur tamamlandı! Kasaly'yi kullanmaya başlayabilirsiniz.
      </div>`
  }
];

let _tutorialStep = 0;
function startTutorial() {
  _tutorialStep = 0;
  renderTutorialStep();
  document.getElementById('tutorial-modal').classList.add('open');
}
function closeTutorial() {
  document.getElementById('tutorial-modal').classList.remove('open');
  const s = D().settings;
  s.tutorialSeen = true;
  saveD();
}
function tutorialNav(dir) {
  const newStep = _tutorialStep + dir;
  // Clamp to valid range
  _tutorialStep = Math.max(0, Math.min(TUTORIAL_STEPS.length - 1, newStep));
  renderTutorialStep();
  // If user was going forward and is now on the last step, just render it (renderTutorialStep handles the button label)
}
function renderTutorialStep() {
  const step = TUTORIAL_STEPS[_tutorialStep];
  document.getElementById('tutorial-step-title').textContent = step.title;
  document.getElementById('tutorial-step-sub').textContent = step.sub;
  document.getElementById('tutorial-body').innerHTML = step.body;
  document.getElementById('tutorial-counter').textContent = `${_tutorialStep + 1} / ${TUTORIAL_STEPS.length}`;
  // Dots
  document.getElementById('tutorial-dots').innerHTML = TUTORIAL_STEPS.map((_, i) =>
    `<div style="height:3px;flex:1;border-radius:2px;background:${i <= _tutorialStep ? 'var(--green)' : 'rgba(255,255,255,.15)'}"></div>`
  ).join('');
  // Buttons
  const prevBtn = document.getElementById('tutorial-prev');
  const nextBtn = document.getElementById('tutorial-next');
  if (prevBtn) prevBtn.style.visibility = _tutorialStep === 0 ? 'hidden' : 'visible';
  if (nextBtn) {
    nextBtn.textContent = _tutorialStep === TUTORIAL_STEPS.length - 1 ? 'Tamamla ✓' : 'Sonraki →';
    nextBtn.onclick = _tutorialStep === TUTORIAL_STEPS.length - 1 ? closeTutorial : () => tutorialNav(1);
  }
}

// ══════════════════════════════════════════════════════════
//  STARTUP
// ══════════════════════════════════════════════════════════
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'DM Sans',sans-serif";
let _slideInterval = null;

// ── Bootstrap: wait for DB to load before starting the app ──
localStorage.removeItem('kt_maint'); // Force wipe local ghost
KasaDB.init().then(() => {
  const s = KasaDB.stats();
  console.info('[KasaDB] Ready —', s.keys, 'keys,', s.estimatedMB, 'MB used');
  initSlides();

  // KasaDB.init() sunucudan session kontrolü yaptı
  // Eğer _uid set edildiyse oturum açık demektir
  if (KasaDB.uid) {
    // Sunucudan gelen session bilgisini sessionStorage'a yaz
    const users = JSON.parse(KasaDB.getItem('kt_users') || '[]');
    const me = users.find(x => x.uid === KasaDB.uid);
    if (me) {
      SESSION = mkSess(me);
      sessionStorage.setItem('kt_sess', JSON.stringify(SESSION));
    } else if (loadSession()) {
      // sessionStorage'dan yükle
    }
    if (!SESSION) {
      document.getElementById('app').style.display = 'none';
      return;
    }
    if (checkMaintenance()) return;
    _D = null;
    document.getElementById('auth-shell').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    initApp();
  } else {
    document.getElementById('app').style.display = 'none';
    if (window.location.search.includes('mode=register')) {
      goAuthPane(1, true);
    }
  }

  document.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      if (curPane === 0) doLogin();
      else if (curPane === 2) fpSubmit1();
    }
  });

  // ── Debounced search handlers (attached after DOM ready) ──
  const _debouncedRenderTable = debounce(renderTable, 220);
  const _debouncedRenderDebts = debounce(renderDebts, 220);
  const _debouncedRenderInvoices = debounce(renderInvoices, 220);
  (function attachDebouncedSearch() {
    const txnSearch = document.getElementById('txn-search');
    if (txnSearch) txnSearch.addEventListener('input', _debouncedRenderTable);
    const debtSearch = document.getElementById('debt-search');
    if (debtSearch) debtSearch.addEventListener('input', _debouncedRenderDebts);
    const invSearch = document.getElementById('inv-search');
    if (invSearch) invSearch.addEventListener('input', _debouncedRenderInvoices);
  })();
}); // end KasaDB.init()


// ══════════════════════════════════════════════════════════
//  ADMIN PANE & ACCOUNT DELETION
// ══════════════════════════════════════════════════════════
function renderAdmin() {
  if (SESSION.username !== 'kasalyadmin2026@gmail.com') { goPage('dashboard'); return; }

  let users = [];
  try { users = JSON.parse(KasaDB.getItem('kt_users') || '[]'); } catch (e) { }
  const nonAdmin = users.filter(u => u.username !== 'kasalyadmin2026@gmail.com');

  document.getElementById('admin-kpi-users').textContent = nonAdmin.length;
  document.getElementById('admin-kpi-sirket').textContent = nonAdmin.filter(u => u.accType === 'sirket').length;
  document.getElementById('admin-kpi-bireysel').textContent = nonAdmin.filter(u => u.accType !== 'sirket').length;
  document.getElementById('admin-kpi-banned').textContent = nonAdmin.filter(u => u.banned).length;

  let dreqs = [];
  try { const s = KasaDB.getItem('kt_delreqs'); if (s) dreqs = JSON.parse(s); } catch (e) { }
  document.getElementById('admin-kpi-delreqs').textContent = dreqs.length;

  const cont = document.getElementById('admin-del-requests');
  if (cont) {
    if (!dreqs.length) {
      cont.innerHTML = `<div style="display:flex;align-items:center;gap:12px;padding:14px 16px;background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.12);border-radius:10px;color:var(--text-muted);font-size:13px">
        <span style="font-size:20px">✅</span><span>Bekleyen silme isteği bulunmuyor.</span>
      </div>`;
    } else {
      cont.innerHTML = dreqs.map((req, i) => `
        <div style="background:rgba(245,158,11,.05);border:1px solid rgba(245,158,11,.18);border-radius:12px;padding:18px;margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
            <div>
              <div style="font-family:'Syne',sans-serif;font-weight:700;font-size:14px">${escHtml(req.username)}</div>
              <div style="font-size:10px;color:var(--text-muted);margin-top:2px;font-family:monospace">${escHtml(req.uid)}</div>
            </div>
            <div style="font-size:11px;color:var(--text-muted)">${escHtml(new Date(req.date).toLocaleString('tr-TR'))}</div>
          </div>
          <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:10px 14px;font-size:12px;margin-bottom:14px;line-height:1.6">
            <span style="color:var(--text-muted)">Sebep:</span> <strong>${escHtml(req.reason || '—')}</strong>
            ${req.text ? `<br><span style="color:var(--text-muted)">${escHtml(req.text)}</span>` : ''}
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-red" style="flex:1;padding:8px;font-size:12px" onclick="adminApproveDelete(${i},'${escHtml(req.uid)}')">🗑 Hesabı Kalıcı Sil</button>
            <button class="btn btn-ghost" style="flex:1;padding:8px;font-size:12px" onclick="adminDenyDelete(${i})">✕ Reddet</button>
          </div>
        </div>`).join('');
    }
  }
  renderAdminUsers();
}

function renderAdminUsers() {
  const tbody = document.getElementById('admin-users-tbody');
  const empty = document.getElementById('admin-users-empty');
  if (!tbody) return;

  const sval = (document.getElementById('admin-user-search')?.value || '').toLowerCase();
  const typeF = document.getElementById('admin-type-f')?.value || '';
  const statusF = document.getElementById('admin-status-f')?.value || '';

  let users = [];
  try { users = JSON.parse(KasaDB.getItem('kt_users') || '[]'); } catch (e) { }
  users = users.filter(u => u.username !== 'kasalyadmin2026@gmail.com');

  if (sval) users = users.filter(u =>
    (u.username || '').toLowerCase().includes(sval) ||
    (u.fullname || '').toLowerCase().includes(sval));
  if (typeF) users = users.filter(u => u.accType === typeF);
  if (statusF === 'active') users = users.filter(u => !u.banned);
  if (statusF === 'banned') users = users.filter(u => u.banned);

  if (!users.length) {
    tbody.innerHTML = '';
    if (empty) empty.style.display = 'flex';
    return;
  }
  if (empty) empty.style.display = 'none';

  tbody.innerHTML = users.map(u => {
    const isBan = !!u.banned;
    const initials = ((u.fullname || u.username || '?').trim().split(' ').map(w => w[0]).join('').substring(0, 2)).toUpperCase();
    const regDate = u.createdAt ? new Date(u.createdAt).toLocaleDateString('tr-TR') : '—';
    const avatarColor = u.accType === 'sirket' ? '#3b82f6,#1d4ed8' : '#22c55e,#166534';
    return `<tr>
      <td>
        <div style="display:flex;align-items:center;gap:10px">
          <div style="width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,${avatarColor});display:flex;align-items:center;justify-content:center;font-family:'Syne',sans-serif;font-weight:800;font-size:12px;color:#fff;flex-shrink:0">${initials}</div>
          <div>
            <div style="font-weight:600;font-size:13px;line-height:1.3">${escHtml(u.fullname || '—')}</div>
            <div style="font-size:11px;color:var(--text-muted)">${escHtml(u.username)}</div>
          </div>
        </div>
      </td>
      <td style="font-size:12px;color:var(--text-muted)">
        ${u.phone ? `<div>📞 ${escHtml(u.phone)}</div>` : ''}
        ${u.email ? `<div>✉️ ${escHtml(u.email)}</div>` : (!u.phone ? '—' : '')}
      </td>
      <td>
        <span class="badge ${u.accType === 'sirket' ? 'badge-blue' : 'badge-green'}">${u.accType === 'sirket' ? '🏢 Şirket' : '👤 Bireysel'}</span>
        ${u.company ? `<div style="font-size:10px;color:var(--text-muted);margin-top:3px">${escHtml(u.company)}</div>` : ''}
      </td>
      <td style="font-size:12px;color:var(--text-muted)">${regDate}</td>
      <td>
        ${isBan
        ? `<div><span class="badge badge-red">⛔ Yasaklı</span>${u.banReason ? `<div style="font-size:10px;color:var(--text-muted);margin-top:3px;max-width:130px;white-space:normal;line-height:1.3">${escHtml(u.banReason)}</div>` : ''}</div>`
        : '<span class="badge badge-green">✅ Aktif</span>'}
      </td>
      <td>
        <div style="display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">
          ${isBan
        ? `<button class="btn btn-ghost" style="padding:5px 10px;font-size:11px;color:var(--green)" onclick="adminToggleBan('${u.uid}',false)">✓ Yasağı Kaldır</button>`
        : `<button class="btn btn-ghost" style="padding:5px 10px;font-size:11px;color:var(--yellow)" onclick="openBanModal('${u.uid}')">⛔ Yasakla</button>`}
          <button class="btn btn-ghost" style="padding:5px 10px;font-size:11px;color:var(--red)" onclick="adminHardDelete('${u.uid}')">🗑 Sil</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

let _banTargetUid = null;
function openBanModal(uid) {
  _banTargetUid = uid;
  document.getElementById('ban-reason-input').value = '';
  document.getElementById('ban-reason-modal').classList.add('open');
}

async function submitBanReason() {
  const reason = document.getElementById('ban-reason-input').value.trim();
  if (!reason) { toast('Lütfen yasaklama nedeni girin', 'error'); return; }
  try {
    await KasaDB.adminSetBan(_banTargetUid, true, reason);
    closeModal('ban-reason-modal');
    toast('Kullanıcı yasaklandı', 'ok');
    renderAdminUsers();
  } catch (e) { toast('Hata: ' + e.message, 'error'); }
}

async function adminToggleBan(uid, isBanned) {
  try {
    await KasaDB.adminSetBan(uid, isBanned, '');
    toast(isBanned ? 'Kullanıcı yasaklandı' : 'Kullanıcı yasağı kaldırıldı', 'ok');
    renderAdminUsers();
  } catch (e) { toast('Hata: ' + e.message, 'error'); }
}

async function adminHardDelete(uid) {
  try {
    const val = await showConfirm('Kullanıcı silinsin mi?', 'Kullanıcının tüm verileri dönülemez şekilde silinecektir. Devam edilsin mi?');
    if (!val) return;
    await KasaDB.adminDeleteUser(uid);
    toast('Kullanıcı ve verileri silindi', 'ok');
    renderAdmin();
  } catch (e) { toast('Hata: ' + e.message, 'error'); }
}

async function adminApproveDelete(idx, uid) {
  const dreqs = JSON.parse(KasaDB.getItem('kt_delreqs') || '[]');
  try {
    await KasaDB.adminDeleteUser(uid);
    dreqs.splice(idx, 1);
    KasaDB.setItem('kt_delreqs', JSON.stringify(dreqs));
    toast('Hesap tamamen silindi', 'ok');
    renderAdmin();
  } catch (e) { toast('Hata: ' + e.message, 'error'); }
}

function adminDenyDelete(idx) {
  const dreqs = JSON.parse(KasaDB.getItem('kt_delreqs') || '[]');
  dreqs.splice(idx, 1);
  KasaDB.setItem('kt_delreqs', JSON.stringify(dreqs));
  toast('Silme isteği reddedildi');
  renderAdmin();
}

function openDeleteAccountModal() {
  document.getElementById('da-reason-sel').value = '';
  document.getElementById('da-reason-txt').value = '';
  document.getElementById('da-reason-txt').style.display = 'none';
  document.getElementById('da-password').value = '';
  document.getElementById('da-confirm-text').value = '';
  document.getElementById('delete-account-modal').classList.add('open');
}

async function submitDeleteAccount() {
  const rs = document.getElementById('da-reason-sel').value;
  const rt = document.getElementById('da-reason-txt').value;
  const pw = document.getElementById('da-password').value;
  const ct = document.getElementById('da-confirm-text').value;

  if (!pw) { toast('Lütfen şifrenizi girin', 'error'); return; }
  if (ct !== 'Hesabımı Kapatmak İstiyorum') { toast('Lütfen onay metnini doğru yazın', 'error'); return; }

  // Şifreyi MongoDB bcrypt ile API üzerinden doğrula
  try {
    const vRes = await KasaDB._api('POST', '/api/verify-password', { password: pw });
    if (!vRes.ok) { toast('Şifreniz yanlış', 'error'); return; }
  } catch (e) {
    toast('Şifre doğrulanamadı: ' + e.message, 'error'); return;
  }

  let dreqs = [];
  try { dreqs = JSON.parse(KasaDB.getItem('kt_delreqs') || '[]'); } catch (e) { }

  if (dreqs.some(x => x.uid === SESSION.uid)) {
    toast('Zaten incelenen bir silme isteğiniz var.', 'error');
    closeModal('delete-account-modal');
    return;
  }

  dreqs.push({
    uid: SESSION.uid,
    username: SESSION.username,
    reason: rs,
    text: rt,
    date: new Date().toISOString()
  });
  KasaDB.setItem('kt_delreqs', JSON.stringify(dreqs));
  toast('Silme isteğiniz yöneticilere iletildi.');
  closeModal('delete-account-modal');
}

function checkMaintenance() {
  // Mechanism temporarily disabled to fix the infinite lock issue.
  return false;
}
// ══════════════════════════════════════════════════════════
//  BİREYSEL: KREDİ & TAKSİT TAKİBİ
// ══════════════════════════════════════════════════════════
function renderCredits() {
  const d = D();
  const credits = d.credits || [];
  const now = new Date();

  // KPI hesapları
  const active = credits.filter(c => c.status === 'active');
  const totalDebt = active.reduce((a, c) => a + c.remaining, 0);
  const totalMonthly = active.reduce((a, c) => a + (c.monthlyPayment || 0), 0);
  const overdue = active.filter(c => c.nextPayDate && new Date(c.nextPayDate) < now);

  document.getElementById('credit-total-debt').textContent = fmt(totalDebt);
  document.getElementById('credit-monthly').textContent = fmt(totalMonthly);
  document.getElementById('credit-overdue-count').textContent = overdue.length;

  // Badge güncelle
  const badge = document.getElementById('credit-badge');
  if (badge) { badge.textContent = overdue.length; badge.style.display = overdue.length ? 'flex' : 'none'; }

  const grid = document.getElementById('credit-grid');
  const empty = document.getElementById('credit-empty');
  if (!credits.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  const typeLabels = { konut: '🏠 Konut Kredisi', taşıt: '🚗 Taşıt Kredisi', ihtiyaç: '💳 İhtiyaç Kredisi', taksit: '🛍️ Taksitli Alım', diğer: '📋 Diğer' };

  grid.innerHTML = credits.map(c => {
    const paidAmt = c.totalAmount - c.remaining;
    const pct = Math.min(100, Math.round((paidAmt / c.totalAmount) * 100));
    const isOver = c.nextPayDate && new Date(c.nextPayDate) < now && c.status === 'active';
    const isPaid = c.status === 'paid';
    const monthsLeft = c.monthlyPayment > 0 ? Math.ceil(c.remaining / c.monthlyPayment) : 0;
    return `<div class="card goal-card ${isPaid ? 'debt-faded' : ''}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
          <span class="badge badge-blue">${typeLabels[c.type] || c.type}</span>
          ${isOver ? '<span class="badge badge-red">⚠️ Gecikti</span>' : ''}
          ${isPaid ? '<span class="badge badge-gray">✓ Kapandı</span>' : ''}
        </div>
        <div class="action-btns">
          ${!isPaid ? `<button class="icon-btn pay" onclick="payCreditInstallment(${c.id})" title="Taksit Öde">💳</button>` : ''}
          <button class="icon-btn edit" onclick="openCreditModal(${c.id})">✏️</button>
          <button class="icon-btn del" onclick="deleteCredit(${c.id})">🗑</button>
        </div>
      </div>
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;margin-bottom:2px">${escHtml(c.name)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${escHtml(c.bank || '')}${c.interestRate ? ' · %' + c.interestRate + ' faiz' : ''}</div>
      <div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:12px">
        <span>Ödenen: <strong style="color:var(--green)">${fmt(paidAmt)}</strong></span>
        <span style="font-family:'Syne',sans-serif;font-size:15px;font-weight:800;color:var(--red)">${fmt(c.remaining)}</span>
      </div>
      <div class="progress-bar"><div class="progress-fill-red" style="width:${pct}%"></div></div>
      <div style="display:flex;justify-content:space-between;margin-top:7px;font-size:11px;color:var(--text-muted)">
        <span>%${pct} ödendi · ${monthsLeft > 0 ? monthsLeft + ' taksit kaldı' : 'son taksit'} · Aylık ${fmt(c.monthlyPayment)}</span>
        <span>${c.nextPayDate ? '📅 ' + new Date(c.nextPayDate).toLocaleDateString('tr-TR') : ''}</span>
      </div>
    </div>`;
  }).join('');
}

function openCreditModal(id = null) {
  ['cr-name', 'cr-bank', 'cr-desc'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('cr-total').value = '';
  document.getElementById('cr-remaining').value = '';
  document.getElementById('cr-monthly').value = '';
  document.getElementById('cr-rate').value = '';
  document.getElementById('cr-nextpay').value = '';
  document.getElementById('cr-type').value = 'ihtiyaç';
  document.getElementById('cr-id').value = '';
  document.getElementById('cr-modal-title').textContent = id ? 'Kredi Düzenle' : 'Kredi / Taksit Ekle';
  if (id) {
    const c = (D().credits || []).find(x => x.id === id);
    if (!c) return;
    document.getElementById('cr-name').value = c.name;
    document.getElementById('cr-bank').value = c.bank || '';
    document.getElementById('cr-type').value = c.type || 'ihtiyaç';
    document.getElementById('cr-total').value = c.totalAmount;
    document.getElementById('cr-remaining').value = c.remaining;
    document.getElementById('cr-monthly').value = c.monthlyPayment;
    document.getElementById('cr-rate').value = c.interestRate || '';
    document.getElementById('cr-nextpay').value = c.nextPayDate || '';
    document.getElementById('cr-desc').value = c.desc || '';
    document.getElementById('cr-id').value = id;
  }
  document.getElementById('credit-modal').classList.add('open');
}

function saveCredit() {
  if (!requireWrite()) return;
  const name = document.getElementById('cr-name').value.trim();
  const totalAmount = parseFloat(document.getElementById('cr-total').value) || 0;
  const remaining = parseFloat(document.getElementById('cr-remaining').value) || 0;
  const monthlyPayment = parseFloat(document.getElementById('cr-monthly').value) || 0;
  if (!name) { toast('Kredi adı zorunludur', 'error'); return; }
  if (totalAmount <= 0) { toast('Toplam tutar zorunludur', 'error'); return; }
  const d = D();
  if (!d.credits) d.credits = [];
  const eid = document.getElementById('cr-id').value;
  const obj = {
    id: eid ? Number(eid) : uid(), name,
    bank: document.getElementById('cr-bank').value.trim(),
    type: document.getElementById('cr-type').value,
    totalAmount, remaining: remaining || totalAmount, monthlyPayment,
    interestRate: parseFloat(document.getElementById('cr-rate').value) || 0,
    nextPayDate: document.getElementById('cr-nextpay').value,
    desc: document.getElementById('cr-desc').value.trim(),
    status: remaining <= 0 ? 'paid' : 'active',
    createdAt: new Date().toISOString()
  };
  if (eid) { d.credits[d.credits.findIndex(x => x.id === Number(eid))] = obj; addLog('edit', 'credit', 'Kredi düzenlendi: ' + name, fmt(totalAmount)); toast('Güncellendi ✓'); }
  else { d.credits.push(obj); addLog('add', 'credit', 'Kredi eklendi: ' + name, fmt(totalAmount)); toast('Eklendi ✓'); }
  saveD(); closeModal('credit-modal'); renderCredits();
}

function payCreditInstallment(id) {
  const d = D();
  const c = (d.credits || []).find(x => x.id === id);
  if (!c) return;
  const amt = c.monthlyPayment || 0;
  c.remaining = Math.max(0, c.remaining - amt);
  if (c.remaining <= 0) c.status = 'paid';
  // Sonraki ödeme tarihini 1 ay ilerlet
  if (c.nextPayDate) {
    const nd = new Date(c.nextPayDate);
    nd.setMonth(nd.getMonth() + 1);
    c.nextPayDate = nd.toISOString().split('T')[0];
  }
  // İşlem kaydı oluştur
  d.txns.push({ id: uid(), type: 'expense', cat: 'Kredi/Taksit', desc: c.name + ' taksit ödemesi', amount: amt, date: today(), note: '' });
  addLog('pay', 'credit', c.name + ' taksit ödendi', fmt(amt));
  saveD(); renderCredits(); toast('Taksit ödendi ✓');
}

async function deleteCredit(id) {
  const ok = await confirmD('Bu krediyi silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const c = (d.credits || []).find(x => x.id === id);
  addLog('delete', 'credit', 'Kredi silindi: ' + (c ? c.name : '?'), '');
  d.credits = (d.credits || []).filter(x => x.id !== id);
  saveD(); renderCredits(); toast('Silindi');
}

// ══════════════════════════════════════════════════════════
//  BİREYSEL: ABONELİK TAKİBİ
// ══════════════════════════════════════════════════════════
function renderSubscriptions() {
  const d = D();
  const subs = d.subscriptions || [];
  const now = new Date();
  const todayStr = today();

  // Otomatik yenileme — oturumda sadece 1 kez çalışır (performans)
  const _renewKey = 'subs_renewed_' + todayStr;
  if (!sessionStorage.getItem(_renewKey)) {
    let changed = false;
    subs.forEach(s => {
      if (s.status !== 'active' || !s.nextDate) return;
      const next = new Date(s.nextDate);
      if (next <= now) {
        d.txns.push({ id: uid(), type: 'expense', cat: 'Fatura/Abonelik', desc: s.name + ' abonelik yenileme', amount: s.amount, date: todayStr, note: 'Otomatik kayıt' });
        const nd = new Date(s.nextDate);
        if (s.period === 'monthly') nd.setMonth(nd.getMonth() + 1);
        else if (s.period === 'yearly') nd.setFullYear(nd.getFullYear() + 1);
        else if (s.period === 'weekly') nd.setDate(nd.getDate() + 7);
        else if (s.period === 'quarterly') nd.setMonth(nd.getMonth() + 3);
        s.nextDate = nd.toISOString().split('T')[0];
        s.lastPaid = todayStr;
        changed = true;
        addLog('pay', 'subscription', s.name + ' otomatik yenilendi', fmt(s.amount));
      }
    });
    if (changed) { saveD(); sessionStorage.setItem(_renewKey, '1'); }
    else sessionStorage.setItem(_renewKey, '1');
  }

  const active = subs.filter(s => s.status === 'active');
  const monthlyTotal = active.reduce((a, s) => {
    if (s.period === 'monthly') return a + s.amount;
    if (s.period === 'yearly') return a + s.amount / 12;
    if (s.period === 'weekly') return a + s.amount * 4.33;
    if (s.period === 'quarterly') return a + s.amount / 3;
    return a + s.amount;
  }, 0);
  const yearlyTotal = monthlyTotal * 12;
  const upcoming7 = active.filter(s => {
    if (!s.nextDate) return false;
    const diff = (new Date(s.nextDate) - now) / 86400000;
    return diff >= 0 && diff <= 7;
  });

  document.getElementById('subs-monthly-total').textContent = fmt(monthlyTotal);
  document.getElementById('subs-yearly-total').textContent = fmt(yearlyTotal);
  document.getElementById('subs-upcoming-count').textContent = upcoming7.length;
  const badge = document.getElementById('subs-badge');
  if (badge) { badge.textContent = upcoming7.length; badge.style.display = upcoming7.length ? 'flex' : 'none'; }

  const periodLabel = { monthly: 'Aylık', yearly: 'Yıllık', weekly: 'Haftalık', quarterly: '3 Aylık' };
  const catIcons = { 'Müzik': '🎵', 'Video': '📺', 'Oyun': '🎮', 'Yazılım': '💻', 'Spor': '💪', 'Haber': '📰', 'Bulut': '☁️', 'Diğer': '📋' };

  const grid = document.getElementById('subs-grid');
  const empty = document.getElementById('subs-empty');
  if (!subs.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  grid.innerHTML = subs.map(s => {
    const daysLeft = s.nextDate ? Math.ceil((new Date(s.nextDate) - now) / 86400000) : null;
    const isSoon = daysLeft !== null && daysLeft <= 7 && daysLeft >= 0;
    const isOver = daysLeft !== null && daysLeft < 0;
    const isPaused = s.status === 'paused';
    const icon = catIcons[s.category] || '📋';
    return `<div class="card goal-card ${isPaused ? 'debt-faded' : ''}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
          <span class="badge badge-blue">${icon} ${s.category || 'Diğer'}</span>
          ${isSoon ? '<span class="badge badge-yellow">⚡ ' + daysLeft + ' gün</span>' : ''}
          ${isOver ? '<span class="badge badge-red">⚠️ Gecikti</span>' : ''}
          ${isPaused ? '<span class="badge badge-gray">⏸ Durduruldu</span>' : ''}
        </div>
        <div class="action-btns">
          <button class="icon-btn" onclick="toggleSubStatus(${s.id})" title="${isPaused ? 'Aktifleştir' : 'Durdur'}">${isPaused ? '▶️' : '⏸'}</button>
          <button class="icon-btn edit" onclick="openSubModal(${s.id})">✏️</button>
          <button class="icon-btn del" onclick="deleteSub(${s.id})">🗑</button>
        </div>
      </div>
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;margin-bottom:2px">${escHtml(s.name)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${periodLabel[s.period] || s.period}${s.nextDate ? ' · 📅 ' + new Date(s.nextDate).toLocaleDateString('tr-TR') : ''}</div>
      <div style="display:flex;justify-content:space-between;font-size:12px">
        <span style="color:var(--text-muted)">Sonraki yenileme</span>
        <span style="font-family:'Syne',sans-serif;font-size:15px;font-weight:800;color:var(--red)">${fmt(s.amount)}<span style="font-size:10px;font-weight:400;color:var(--text-muted)"> / ${periodLabel[s.period] || ''}</span></span>
      </div>
    </div>`;
  }).join('');
}

function openSubModal(id = null) {
  ['sub-name', 'sub-desc'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('sub-amount').value = '';
  document.getElementById('sub-period').value = 'monthly';
  document.getElementById('sub-category').value = 'Diğer';
  document.getElementById('sub-nextdate').value = '';
  document.getElementById('sub-id').value = '';
  document.getElementById('sub-modal-title').textContent = id ? 'Abonelik Düzenle' : 'Abonelik Ekle';
  if (id) {
    const s = (D().subscriptions || []).find(x => x.id === id);
    if (!s) return;
    document.getElementById('sub-name').value = s.name;
    document.getElementById('sub-amount').value = s.amount;
    document.getElementById('sub-period').value = s.period;
    document.getElementById('sub-category').value = s.category || 'Diğer';
    document.getElementById('sub-nextdate').value = s.nextDate || '';
    document.getElementById('sub-desc').value = s.desc || '';
    document.getElementById('sub-id').value = id;
  }
  document.getElementById('sub-modal').classList.add('open');
}

function saveSub() {
  if (!requireWrite()) return;
  const name = document.getElementById('sub-name').value.trim();
  const amount = parseFloat(document.getElementById('sub-amount').value) || 0;
  if (!name) { toast('Abonelik adı zorunludur', 'error'); return; }
  if (amount <= 0) { toast('Tutar zorunludur', 'error'); return; }
  const d = D();
  if (!d.subscriptions) d.subscriptions = [];
  const eid = document.getElementById('sub-id').value;
  const obj = {
    id: eid ? Number(eid) : uid(), name, amount,
    period: document.getElementById('sub-period').value,
    category: document.getElementById('sub-category').value,
    nextDate: document.getElementById('sub-nextdate').value,
    desc: document.getElementById('sub-desc').value.trim(),
    status: 'active', createdAt: new Date().toISOString()
  };
  if (eid) { d.subscriptions[d.subscriptions.findIndex(x => x.id === Number(eid))] = obj; toast('Güncellendi ✓'); }
  else { d.subscriptions.push(obj); addLog('add', 'subscription', 'Abonelik eklendi: ' + name, fmt(amount)); toast('Eklendi ✓'); }
  saveD(); closeModal('sub-modal'); renderSubscriptions();
}

function toggleSubStatus(id) {
  const d = D();
  const s = (d.subscriptions || []).find(x => x.id === id);
  if (!s) return;
  s.status = s.status === 'active' ? 'paused' : 'active';
  saveD(); renderSubscriptions();
  toast(s.status === 'active' ? 'Abonelik aktifleştirildi' : 'Abonelik durduruldu', 'info');
}

async function deleteSub(id) {
  const ok = await confirmD('Bu aboneliği silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const s = (d.subscriptions || []).find(x => x.id === id);
  addLog('delete', 'subscription', 'Abonelik silindi: ' + (s ? s.name : '?'), '');
  d.subscriptions = (d.subscriptions || []).filter(x => x.id !== id);
  saveD(); renderSubscriptions(); toast('Silindi');
}

// ══════════════════════════════════════════════════════════
//  TİCARİ: MÜŞTERİ & TEDARİKÇİ (CRM Lite)
// ══════════════════════════════════════════════════════════
function renderCustomers() {
  const d = D();
  const customers = d.customers || [];
  const search = (document.getElementById('cust-search') || {}).value?.toLowerCase() || '';
  const typeF = (document.getElementById('cust-type-f') || {}).value || '';

  const totals = {
    customer: customers.filter(c => c.type === 'customer').length,
    supplier: customers.filter(c => c.type === 'supplier').length,
    totalReceivable: customers.filter(c => c.type === 'customer').reduce((a, c) => a + (c.balance || 0), 0),
    totalPayable: customers.filter(c => c.type === 'supplier').reduce((a, c) => a + (c.balance || 0), 0),
  };
  document.getElementById('cust-count-customer').textContent = totals.customer;
  document.getElementById('cust-count-supplier').textContent = totals.supplier;
  document.getElementById('cust-receivable').textContent = fmt(totals.totalReceivable);
  document.getElementById('cust-payable').textContent = fmt(totals.totalPayable);

  let data = [...customers];
  if (search) data = data.filter(c => (c.name || '').toLowerCase().includes(search) || (c.phone || '').includes(search) || (c.email || '').toLowerCase().includes(search));
  if (typeF) data = data.filter(c => c.type === typeF);

  const grid = document.getElementById('cust-grid');
  const empty = document.getElementById('cust-empty');
  if (!data.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  grid.innerHTML = data.map(c => {
    const isCustomer = c.type === 'customer';
    const txnCount = (d.txns || []).filter(t => t.customerId === c.id).length;
    const bal = c.balance || 0;
    const initials = (c.name || '?').trim().split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase();
    return `<div class="card goal-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
          <span class="badge ${isCustomer ? 'badge-green' : 'badge-blue'}">${isCustomer ? '🤝 Müşteri' : '🏭 Tedarikçi'}</span>
        </div>
        <div class="action-btns">
          <button class="icon-btn edit" onclick="openCustModal(${c.id})">✏️</button>
          <button class="icon-btn del" onclick="deleteCustomer(${c.id})">🗑</button>
        </div>
      </div>
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:10px">
        <div style="width:42px;height:42px;border-radius:12px;background:${isCustomer ? 'rgba(34,197,94,.12)' : 'rgba(59,130,246,.12)'};display:flex;align-items:center;justify-content:center;font-family:'Syne',sans-serif;font-weight:800;font-size:14px;flex-shrink:0;color:${isCustomer ? 'var(--green)' : 'var(--cyan)'}">${initials}</div>
        <div>
          <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700">${escHtml(c.name)}</div>
          <div style="font-size:12px;color:var(--text-muted)">${c.company ? escHtml(c.company) + ' · ' : ''}${txnCount} işlem</div>
        </div>
      </div>
      <div style="display:flex;gap:10px;font-size:11px;color:var(--text-muted);flex-wrap:wrap;margin-bottom:10px">
        ${c.phone ? `<span>📞 ${escHtml(c.phone)}</span>` : ''}
        ${c.email ? `<span>✉️ ${escHtml(c.email)}</span>` : ''}
      </div>
      <div style="display:flex;justify-content:space-between;font-size:12px">
        <span style="color:var(--text-muted)">${isCustomer ? 'Cari Bakiye' : 'Borç Bakiyesi'}</span>
        <span style="font-family:'Syne',sans-serif;font-size:15px;font-weight:800;color:${bal >= 0 ? 'var(--green)' : 'var(--red)'}">${fmt(Math.abs(bal))}</span>
      </div>
    </div>`;
  }).join('');
}

function openCustModal(id = null) {
  ['cust-name', 'cust-company', 'cust-phone', 'cust-email', 'cust-address', 'cust-taxno', 'cust-notes'].forEach(k => document.getElementById(k).value = '');
  document.getElementById('cust-type-sel').value = 'customer';
  document.getElementById('cust-balance').value = '0';
  document.getElementById('cust-id').value = '';
  document.getElementById('cust-modal-title').textContent = id ? 'Kişi Düzenle' : 'Müşteri / Tedarikçi Ekle';
  if (id) {
    const c = (D().customers || []).find(x => x.id === id);
    if (!c) return;
    document.getElementById('cust-name').value = c.name;
    document.getElementById('cust-company').value = c.company || '';
    document.getElementById('cust-phone').value = c.phone || '';
    document.getElementById('cust-email').value = c.email || '';
    document.getElementById('cust-address').value = c.address || '';
    document.getElementById('cust-taxno').value = c.taxNo || '';
    document.getElementById('cust-notes').value = c.notes || '';
    document.getElementById('cust-type-sel').value = c.type || 'customer';
    document.getElementById('cust-balance').value = c.balance || 0;
    document.getElementById('cust-id').value = id;
  }
  document.getElementById('customer-modal').classList.add('open');
}

function saveCustomer() {
  if (!requireWrite()) return;
  const name = document.getElementById('cust-name').value.trim();
  if (!name) { toast('İsim zorunludur', 'error'); return; }
  const d = D();
  if (!d.customers) d.customers = [];
  const eid = document.getElementById('cust-id').value;
  const obj = {
    id: eid ? Number(eid) : uid(), name,
    type: document.getElementById('cust-type-sel').value,
    company: document.getElementById('cust-company').value.trim(),
    phone: document.getElementById('cust-phone').value.trim(),
    email: document.getElementById('cust-email').value.trim(),
    address: document.getElementById('cust-address').value.trim(),
    taxNo: document.getElementById('cust-taxno').value.trim(),
    notes: document.getElementById('cust-notes').value.trim(),
    balance: parseFloat(document.getElementById('cust-balance').value) || 0,
    createdAt: new Date().toISOString()
  };
  if (eid) { d.customers[d.customers.findIndex(x => x.id === Number(eid))] = obj; toast('Güncellendi ✓'); }
  else { d.customers.push(obj); addLog('add', 'customer', 'Müşteri/Tedarikçi eklendi: ' + name, ''); toast('Eklendi ✓'); }
  saveD(); closeModal('customer-modal'); renderCustomers();
}

async function deleteCustomer(id) {
  const ok = await confirmD('Bu kişiyi silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const c = (d.customers || []).find(x => x.id === id);
  addLog('delete', 'customer', 'Müşteri silindi: ' + (c ? c.name : '?'), '');
  d.customers = (d.customers || []).filter(x => x.id !== id);
  saveD(); renderCustomers(); toast('Silindi');
}

// ══════════════════════════════════════════════════════════
//  TİCARİ: STOK & ÜRÜN TAKİBİ
// ══════════════════════════════════════════════════════════
function renderStock() {
  const d = D();
  const items = d.stock || [];
  const search = (document.getElementById('stock-search') || {}).value?.toLowerCase() || '';
  const catF = (document.getElementById('stock-cat-f') || {}).value || '';

  const totalValue = items.reduce((a, i) => a + (i.quantity * i.buyPrice), 0);
  const lowStock = items.filter(i => i.quantity <= (i.minStock || 5));
  const totalItems = items.reduce((a, i) => a + i.quantity, 0);

  document.getElementById('stock-total-value').textContent = fmt(totalValue);
  document.getElementById('stock-low-count').textContent = lowStock.length;
  document.getElementById('stock-total-items').textContent = totalItems;

  let data = [...items];
  if (search) data = data.filter(i => (i.name || '').toLowerCase().includes(search) || (i.sku || '').toLowerCase().includes(search));
  if (catF) data = data.filter(i => i.category === catF);
  data.sort((a, b) => a.quantity - (a.minStock || 5) > b.quantity - (b.minStock || 5) ? 1 : -1); // kritik stok önce

  const grid = document.getElementById('stock-grid');
  const empty = document.getElementById('stock-empty');
  if (!items.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  grid.innerHTML = data.map(item => {
    const isLow = item.quantity <= (item.minStock || 5);
    const isOut = item.quantity <= 0;
    const profit = item.sellPrice > 0 ? ((item.sellPrice - item.buyPrice) / item.buyPrice * 100).toFixed(1) : 0;
    return `<div class="card goal-card${isOut ? ' debt-faded' : ''}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
          ${isOut ? '<span class="badge badge-red">📦 Tükendi</span>' : isLow ? '<span class="badge badge-yellow">⚠️ Az Kaldı</span>' : '<span class="badge badge-green">✓ Stokta</span>'}
          ${item.category ? `<span class="badge badge-gray">${escHtml(item.category)}</span>` : ''}
        </div>
        <div class="action-btns">
          <button class="icon-btn pay" onclick="adjustStock(${item.id})" title="Stok Güncelle">📦</button>
          <button class="icon-btn edit" onclick="openStockModal(${item.id})">✏️</button>
          <button class="icon-btn del" onclick="deleteStockItem(${item.id})">🗑</button>
        </div>
      </div>
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;margin-bottom:2px">${escHtml(item.name)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${item.sku ? 'SKU: ' + escHtml(item.sku) + ' · ' : ''}${item.quantity} ${item.unit || 'adet'} stokta</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;text-align:center">
        <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px 6px">
          <div style="font-size:9px;color:var(--text-muted);margin-bottom:2px">STOK</div>
          <div style="font-family:'Syne',sans-serif;font-size:18px;font-weight:800;color:${isOut ? 'var(--red)' : isLow ? 'var(--yellow)' : 'var(--green)'}">${item.quantity}</div>
          <div style="font-size:9px;color:var(--text-muted)">${item.unit || 'adet'}</div>
        </div>
        <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px 6px">
          <div style="font-size:9px;color:var(--text-muted);margin-bottom:2px">ALIŞ / SATIŞ</div>
          <div style="font-family:'Syne',sans-serif;font-size:12px;font-weight:700">${fmt(item.buyPrice)}</div>
          <div style="font-family:'Syne',sans-serif;font-size:12px;font-weight:700;color:var(--green)">${fmt(item.sellPrice || 0)}</div>
        </div>
        <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px 6px">
          <div style="font-size:9px;color:var(--text-muted);margin-bottom:2px">KÂR MARJI</div>
          <div style="font-family:'Syne',sans-serif;font-size:16px;font-weight:800;color:var(--cyan)">${profit > 0 ? '+' + profit + '%' : '—'}</div>
        </div>
      </div>
    </div>`;
  }).join('');
}

function openStockModal(id = null) {
  ['stock-name', 'stock-sku', 'stock-category', 'stock-unit'].forEach(k => { const el = document.getElementById(k); if (el) el.value = ''; });
  ['stock-quantity', 'stock-buy-price', 'stock-sell-price', 'stock-min-stock'].forEach(k => { const el = document.getElementById(k); if (el) el.value = ''; });
  document.getElementById('stock-id').value = '';
  document.getElementById('stock-modal-title').textContent = id ? 'Ürün Düzenle' : 'Ürün / Stok Ekle';
  if (id) {
    const item = (D().stock || []).find(x => x.id === id);
    if (!item) return;
    document.getElementById('stock-name').value = item.name;
    document.getElementById('stock-sku').value = item.sku || '';
    document.getElementById('stock-category').value = item.category || '';
    document.getElementById('stock-unit').value = item.unit || 'adet';
    document.getElementById('stock-quantity').value = item.quantity;
    document.getElementById('stock-buy-price').value = item.buyPrice;
    document.getElementById('stock-sell-price').value = item.sellPrice || '';
    document.getElementById('stock-min-stock').value = item.minStock || 5;
    document.getElementById('stock-id').value = id;
  }
  document.getElementById('stock-modal').classList.add('open');
}

function saveStockItem() {
  if (!requireWrite()) return;
  const name = document.getElementById('stock-name').value.trim();
  const quantity = parseInt(document.getElementById('stock-quantity').value) || 0;
  const buyPrice = parseFloat(document.getElementById('stock-buy-price').value) || 0;
  if (!name) { toast('Ürün adı zorunludur', 'error'); return; }
  const d = D();
  if (!d.stock) d.stock = [];
  const eid = document.getElementById('stock-id').value;
  const obj = {
    id: eid ? Number(eid) : uid(), name,
    sku: document.getElementById('stock-sku').value.trim(),
    category: document.getElementById('stock-category').value.trim(),
    unit: document.getElementById('stock-unit').value || 'adet',
    quantity, buyPrice,
    sellPrice: parseFloat(document.getElementById('stock-sell-price').value) || 0,
    minStock: parseInt(document.getElementById('stock-min-stock').value) || 5,
    updatedAt: new Date().toISOString()
  };
  if (eid) { d.stock[d.stock.findIndex(x => x.id === Number(eid))] = obj; toast('Güncellendi ✓'); }
  else { d.stock.push(obj); addLog('add', 'stock', 'Ürün eklendi: ' + name, quantity + ' adet'); toast('Eklendi ✓'); }
  saveD(); closeModal('stock-modal'); renderStock();
}

function adjustStock(id) {
  const item = (D().stock || []).find(x => x.id === id);
  if (!item) return;
  const val = prompt(`"${item.name}" için yeni stok miktarı girin (mevcut: ${item.quantity}):`);
  if (val === null) return;
  const n = parseInt(val);
  if (isNaN(n) || n < 0) { toast('Geçersiz miktar', 'error'); return; }
  const d = D();
  const i = d.stock.findIndex(x => x.id === id);
  const diff = n - d.stock[i].quantity;
  d.stock[i].quantity = n;
  d.stock[i].updatedAt = new Date().toISOString();
  if (diff !== 0) addLog('edit', 'stock', item.name + ' stok güncellendi', (diff > 0 ? '+' : '') + diff);
  saveD(); renderStock(); toast('Stok güncellendi ✓');
}

async function deleteStockItem(id) {
  const ok = await confirmD('Bu ürünü silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const item = (d.stock || []).find(x => x.id === id);
  d.stock = (d.stock || []).filter(x => x.id !== id);
  addLog('delete', 'stock', 'Ürün silindi: ' + (item ? item.name : '?'), '');
  saveD(); renderStock(); toast('Silindi');
}

// ══════════════════════════════════════════════════════════
//  TİCARİ: PROJE & İŞ TAKİBİ
// ══════════════════════════════════════════════════════════
function renderProjects() {
  const d = D();
  const projects = d.projects || [];

  const active = projects.filter(p => p.status === 'active').length;
  const completed = projects.filter(p => p.status === 'completed').length;
  const totalRevenue = projects.filter(p => p.status === 'completed').reduce((a, p) => a + (p.budget || 0), 0);
  const totalCost = projects.reduce((a, p) => a + (p.spent || 0), 0);

  document.getElementById('proj-active-count').textContent = active;
  document.getElementById('proj-completed-count').textContent = completed;
  document.getElementById('proj-total-revenue').textContent = fmt(totalRevenue);

  const badge = document.getElementById('proj-badge');
  if (badge) { badge.textContent = active; badge.style.display = active ? 'flex' : 'none'; }

  const statusLabel = { active: '🟢 Devam Ediyor', completed: '✅ Tamamlandı', paused: '⏸ Beklemede', cancelled: '❌ İptal' };
  const statusColor = { active: 'badge-green', completed: 'badge-blue', paused: 'badge-yellow', cancelled: 'badge-red' };

  const grid = document.getElementById('proj-grid');
  const empty = document.getElementById('proj-empty');
  if (!projects.length) { grid.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  grid.innerHTML = projects.map(p => {
    const tasksDone = (p.tasks || []).filter(t => t.done).length;
    const tasksTotal = (p.tasks || []).length;
    const taskPct = tasksTotal > 0 ? Math.round((tasksDone / tasksTotal) * 100) : 0;
    const budgetPct = p.budget > 0 ? Math.min(100, Math.round(((p.spent || 0) / p.budget) * 100)) : 0;
    const isOverBudget = p.budget > 0 && (p.spent || 0) > p.budget;
    const now = new Date();
    const daysLeft = p.deadline ? Math.ceil((new Date(p.deadline) - now) / 86400000) : null;
    const customer = p.customerId ? (d.customers || []).find(c => c.id === p.customerId) : null;
    return `<div class="card goal-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
          <span class="badge ${statusColor[p.status] || 'badge-gray'}">${statusLabel[p.status] || p.status}</span>
          ${isOverBudget ? '<span class="badge badge-red">⚠️ Bütçe Aşıldı</span>' : ''}
          ${daysLeft !== null && daysLeft < 0 ? '<span class="badge badge-red">⚠️ Gecikti</span>' : daysLeft !== null && daysLeft <= 7 ? `<span class="badge badge-yellow">📅 ${daysLeft} gün</span>` : ''}
        </div>
        <div class="action-btns">
          <button class="icon-btn edit" onclick="openProjectModal(${p.id})">✏️</button>
          <button class="icon-btn del" onclick="deleteProject(${p.id})">🗑</button>
        </div>
      </div>
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;margin-bottom:2px">${escHtml(p.name)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${customer ? '👤 ' + escHtml(customer.name) + (p.desc ? ' · ' : '') : ''}${p.desc ? escHtml(p.desc) : ''}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:8px">
        <div>
          <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-bottom:4px">
            <span>Bütçe</span><span>${fmt(p.spent || 0)} / ${fmt(p.budget || 0)}</span>
          </div>
          <div class="progress-bar"><div class="${isOverBudget ? 'progress-fill-red' : 'progress-fill'}" style="width:${budgetPct}%"></div></div>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-bottom:4px">
            <span>Görevler</span><span>${tasksDone}/${tasksTotal} (%${taskPct})</span>
          </div>
          <div class="progress-bar"><div class="progress-fill" style="width:${taskPct}%"></div></div>
        </div>
      </div>
    </div>`;
  }).join('');
}

function openProjectModal(id = null) {
  ['proj-name', 'proj-desc'].forEach(k => { const el = document.getElementById(k); if (el) el.value = ''; });
  document.getElementById('proj-budget').value = '';
  document.getElementById('proj-spent').value = '';
  document.getElementById('proj-deadline').value = '';
  document.getElementById('proj-status-sel').value = 'active';
  document.getElementById('proj-customer-sel').innerHTML = '<option value="">— Müşteri seçin —</option>' +
    (D().customers || []).filter(c => c.type === 'customer').map(c => `<option value="${c.id}">${escHtml(c.name)}</option>`).join('');
  document.getElementById('proj-id').value = '';
  document.getElementById('proj-modal-title').textContent = id ? 'Proje Düzenle' : 'Proje Ekle';
  document.getElementById('proj-tasks-container').innerHTML = '';
  if (id) {
    const p = (D().projects || []).find(x => x.id === id);
    if (!p) return;
    document.getElementById('proj-name').value = p.name;
    document.getElementById('proj-desc').value = p.desc || '';
    document.getElementById('proj-budget').value = p.budget || '';
    document.getElementById('proj-spent').value = p.spent || '';
    document.getElementById('proj-deadline').value = p.deadline || '';
    document.getElementById('proj-status-sel').value = p.status || 'active';
    document.getElementById('proj-id').value = id;
    if (p.customerId) document.getElementById('proj-customer-sel').value = p.customerId;
    // Görevler
    const tc = document.getElementById('proj-tasks-container');
    (p.tasks || []).forEach(t => { tc.insertAdjacentHTML('beforeend', _taskRow(t.text, t.done, t.id)); });
  }
  document.getElementById('project-modal').classList.add('open');
}

function _taskRow(text = '', done = false, tid = null) {
  const id = tid || uid();
  return `<div class="task-row" data-tid="${id}" style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
    <input type="checkbox" ${done ? 'checked' : ''} onchange="this.parentElement.querySelector('.task-text').style.textDecoration=this.checked?'line-through':''">
    <input type="text" class="form-input task-text" value="${escHtml(text)}" placeholder="Görev..." style="flex:1${done ? ';text-decoration:line-through' : ''}">
    <button class="icon-btn del" onclick="this.parentElement.remove()" type="button">🗑</button>
  </div>`;
}

function addProjectTask() {
  document.getElementById('proj-tasks-container').insertAdjacentHTML('beforeend', _taskRow());
}

function saveProject() {
  if (!requireWrite()) return;
  const name = document.getElementById('proj-name').value.trim();
  if (!name) { toast('Proje adı zorunludur', 'error'); return; }
  const d = D();
  if (!d.projects) d.projects = [];
  const eid = document.getElementById('proj-id').value;
  // Görevleri topla
  const tasks = [];
  document.querySelectorAll('#proj-tasks-container .task-row').forEach(row => {
    const text = row.querySelector('.task-text').value.trim();
    const done = row.querySelector('input[type=checkbox]').checked;
    const tid = Number(row.dataset.tid);
    if (text) tasks.push({ id: tid || uid(), text, done });
  });
  const custVal = document.getElementById('proj-customer-sel').value;
  const obj = {
    id: eid ? Number(eid) : uid(), name,
    desc: document.getElementById('proj-desc').value.trim(),
    budget: parseFloat(document.getElementById('proj-budget').value) || 0,
    spent: parseFloat(document.getElementById('proj-spent').value) || 0,
    deadline: document.getElementById('proj-deadline').value,
    status: document.getElementById('proj-status-sel').value,
    customerId: custVal ? Number(custVal) : null,
    tasks, updatedAt: new Date().toISOString()
  };
  if (eid) { d.projects[d.projects.findIndex(x => x.id === Number(eid))] = obj; toast('Güncellendi ✓'); }
  else { d.projects.push(obj); addLog('add', 'project', 'Proje eklendi: ' + name, fmt(obj.budget)); toast('Eklendi ✓'); }
  saveD(); closeModal('project-modal'); renderProjects();
}

async function deleteProject(id) {
  const ok = await confirmD('Bu projeyi silmek istiyor musunuz?');
  if (!ok) return;
  const d = D(); const p = (d.projects || []).find(x => x.id === id);
  d.projects = (d.projects || []).filter(x => x.id !== id);
  addLog('delete', 'project', 'Proje silindi: ' + (p ? p.name : '?'), '');
  saveD(); renderProjects(); toast('Silindi');
}

// ══════════════════════════════════════════════════════════
//  TİCARİ: BORDRO & PERSONEL
// ══════════════════════════════════════════════════════════
function renderPayroll() {
  const d = D();
  const employees = d.employees || [];
  const payrolls = d.payrolls || [];
  const now = new Date();
  const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

  const active = employees.filter(e => e.status === 'active');
  const totalGross = active.reduce((a, e) => a + (e.salary || 0), 0);
  // Türkiye: ~%15 işveren primi tahmini
  const totalEmployerCost = totalGross * 1.155;
  const thisMonthPayrolls = payrolls.filter(p => p.month === thisMonth);
  const paidCount = thisMonthPayrolls.filter(p => p.status === 'paid').length;

  document.getElementById('payroll-gross-total').textContent = fmt(totalGross);
  document.getElementById('payroll-employer-total').textContent = fmt(totalEmployerCost);
  document.getElementById('payroll-paid-count').textContent = paidCount + ' / ' + active.length;

  const list = document.getElementById('payroll-list');
  const empty = document.getElementById('payroll-empty');
  if (!active.length) { list.innerHTML = ''; empty.style.display = 'block'; return; }
  empty.style.display = 'none';

  list.innerHTML = active.map(e => {
    const pr = thisMonthPayrolls.find(p => p.empId === e.id);
    const isPaid = pr && pr.status === 'paid';
    const gross = e.salary || 0;
    // Basit Türkiye SGK/vergi tahmini (gerçek hesaplama muhasebe yazılımı gerektirir)
    const sgkEmployee = gross * 0.14;  // %14 SGK işçi
    const gelirVergisi = gross * 0.15; // ~%15 gelir vergisi (kademeli)
    const damga = gross * 0.00759;     // Damga vergisi
    const net = gross - sgkEmployee - gelirVergisi - damga;
    const sgkEmployer = gross * 0.155; // %15.5 SGK işveren
    return `<div class="card goal-card ${isPaid ? 'debt-faded' : ''}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
          <span class="badge ${isPaid ? 'badge-green' : 'badge-yellow'}">${isPaid ? '✓ Bu Ay Ödendi' : '⏳ Ödeme Bekliyor'}</span>
        </div>
        <div class="action-btns" style="gap:8px">
          ${!isPaid ? `<button class="btn btn-green" onclick="payEmployee(${e.id})" style="font-size:12px;padding:5px 12px;border-radius:8px">💰 Öde</button>` : ''}
        </div>
      </div>
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;margin-bottom:2px">${escHtml(e.fname)} ${escHtml(e.lname)}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px">${escHtml(e.pos || '')}${e.dept ? ' · ' + escHtml(e.dept) : ''}</div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;text-align:center">
        <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px 6px">
          <div style="font-size:9px;color:var(--text-muted);margin-bottom:3px">BRÜT</div>
          <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700">${fmt(gross)}</div>
        </div>
        <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px 6px">
          <div style="font-size:9px;color:var(--text-muted);margin-bottom:3px">KESİNTİLER</div>
          <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;color:var(--red)">-${fmt(sgkEmployee + gelirVergisi + damga)}</div>
        </div>
        <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px 6px">
          <div style="font-size:9px;color:var(--text-muted);margin-bottom:3px">NET MAAŞ</div>
          <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;color:var(--green)">${fmt(net)}</div>
        </div>
        <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px 6px">
          <div style="font-size:9px;color:var(--text-muted);margin-bottom:3px">İŞVEREN</div>
          <div style="font-family:'Syne',sans-serif;font-size:13px;font-weight:700;color:var(--yellow)">${fmt(gross + sgkEmployer)}</div>
        </div>
      </div>
    </div>`;
  }).join('');
}

function payEmployee(empId) {
  const d = D();
  if (!d.payrolls) d.payrolls = [];
  const now = new Date();
  const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const emp = (d.employees || []).find(e => e.id === empId);
  if (!emp) return;
  const existing = d.payrolls.find(p => p.empId === empId && p.month === thisMonth);
  if (existing && existing.status === 'paid') { toast('Bu ay maaş zaten ödendi', 'error'); return; }
  const gross = emp.salary || 0;
  const sgk = gross * 0.14;
  const gv = gross * 0.15;
  const damga = gross * 0.00759;
  const net = gross - sgk - gv - damga;
  if (existing) {
    existing.status = 'paid'; existing.paidAt = new Date().toISOString();
  } else {
    d.payrolls.push({ id: uid(), empId, empName: emp.fname + ' ' + emp.lname, month: thisMonth, gross, net, status: 'paid', paidAt: new Date().toISOString() });
  }
  // Gider olarak kaydet
  d.txns.push({ id: uid(), type: 'expense', cat: 'Personel Gideri', desc: emp.fname + ' ' + emp.lname + ' maaş ödemesi (' + thisMonth + ')', amount: gross, date: today(), note: '' });
  addLog('pay', 'payroll', emp.fname + ' ' + emp.lname + ' maaş ödendi', fmt(net) + ' net');
  saveD(); renderPayroll(); if (curPage === 'dashboard') renderDash(); toast(emp.fname + ' ' + emp.lname + ' maaşı ödendi ✓');
}

function exportPayrollReport() {
  const d = D();
  const now = new Date();
  const thisMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const active = (d.employees || []).filter(e => e.status === 'active');
  const rows = [['Çalışan', 'Pozisyon', 'Brüt Maaş', 'SGK İşçi', 'Gelir Vergisi', 'Net Maaş', 'İşveren SGK', 'İşveren Toplam', 'Durum']];
  let totalGross = 0, totalNet = 0, totalEmployer = 0;
  active.forEach(e => {
    const gross = e.salary || 0;
    const sgk = gross * 0.14;
    const gv = gross * 0.15;
    const damga = gross * 0.00759;
    const net = gross - sgk - gv - damga;
    const empSGK = gross * 0.155;
    const pr = (d.payrolls || []).find(p => p.empId === e.id && p.month === thisMonth);
    totalGross += gross; totalNet += net; totalEmployer += gross + empSGK;
    rows.push([e.fname + ' ' + e.lname, e.pos || '', gross.toFixed(2), sgk.toFixed(2), gv.toFixed(2), net.toFixed(2), empSGK.toFixed(2), (gross + empSGK).toFixed(2), pr?.status === 'paid' ? 'Ödendi' : 'Bekliyor']);
  });
  rows.push(['TOPLAM', '', totalGross.toFixed(2), '', '', totalNet.toFixed(2), '', totalEmployer.toFixed(2), '']);
  const csv = '\uFEFF' + rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = `bordro-${thisMonth}.csv`;
  a.click();
  toast('Bordro raporu indirildi ✓');
}