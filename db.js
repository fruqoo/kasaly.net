/**
 * Kasaly — MongoDB API Storage Layer (v6.0)
 * ──────────────────────────────────────────
 * Değişiklikler v6:
 *   - getUsers() → sadece admin çağırabilir (KVKK)
 *   - deleteAccount() yeni endpoint'i destekler
 *   - adminResetPassword() eklendi
 *   - refreshSession() — session süresi dolunca yenile
 *   - Hata mesajları daha açıklayıcı
 */
(function (global) {
  'use strict';

  /* ─── API base URL ─── */
  const API = (function () {
    const h = window.location.hostname;
    if (h === 'localhost' || h === '127.0.0.1') return 'http://127.0.0.1:3000';
    return window.KASALY_API_URL || '';
  })();

  const _mem = Object.create(null);
  let _uid = null;
  let _writeTimer = null;

  /* ─── Fetch helper ─── */
  async function _api(method, path, body) {
    const opts = {
      method,
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' }
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(API + path, opts);
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(json.error || 'Sunucu hatası (' + res.status + ')');
    return json;
  }

  /* ─── Debounced userdata write ─── */
  function _queueDataWrite(jsonStr) {
    if (!_uid) return;
    clearTimeout(_writeTimer);
    _writeTimer = setTimeout(async () => {
      try {
        await _api('PUT', '/api/userdata', { data: JSON.parse(jsonStr) });
      } catch (e) {
        console.error('[KasaDB] Userdata write error', e);
      }
    }, 600);
  }

  /* ─── Synchronous API ─── */
  function getItem(key) {
    return _mem[key] !== undefined ? String(_mem[key]) : localStorage.getItem(key);
  }

  function setItem(key, value) {
    const str = String(value);
    _mem[key] = str;
    if (key === 'kt_d_' + _uid) {
      _queueDataWrite(str);
    } else if (key === 'kt_users') {
      // sadece bellekte
    } else {
      localStorage.setItem(key, str);
    }
  }

  function removeItem(key) {
    delete _mem[key];
    localStorage.removeItem(key);
  }

  /* ─── Init ─── */
  async function init() {
    try {
      // Aktif oturum kontrolü
      const sess = await _api('GET', '/api/session');
      if (sess.loggedIn && sess.user) {
        _uid = sess.user.uid;
        const data = await _api('GET', '/api/userdata');
        const defaultData = { txns: [], debts: [], goals: [], invoices: [], employees: [], logs: [], settings: {} };
        _mem['kt_d_' + _uid] = JSON.stringify(Object.assign(defaultData, data || {}));

        // Kullanıcı listesini sadece admin çeksin
        if (sess.user.username === (window.KASALY_ADMIN_USER || 'kasalyadmin2026@gmail.com')) {
          try {
            const users = await _api('GET', '/api/users');
            _mem['kt_users'] = JSON.stringify(users);
          } catch (e) {
            console.warn('[KasaDB] Admin user list fetch failed', e);
          }
        }
      }
    } catch (e) {
      console.warn('[KasaDB] Init error', e);
    }
  }

  /* ─── Auth ─── */
  async function login(username, password) {
    const res = await _api('POST', '/api/login', { username, password });
    const u = res.user;
    _uid = u.uid;
    const data = await _api('GET', '/api/userdata');
    const defaultData = { txns: [], debts: [], goals: [], invoices: [], employees: [], logs: [], settings: {} };
    _mem['kt_d_' + _uid] = JSON.stringify(Object.assign(defaultData, data || {}));

    // Admin ise kullanıcı listesini de çek
    if (u.username === (window.KASALY_ADMIN_USER || 'kasalyadmin2026@gmail.com')) {
      try {
        const users = await _api('GET', '/api/users');
        _mem['kt_users'] = JSON.stringify(users);
      } catch (e) { /* sessiz hata */ }
    }
    return u;
  }

  async function register(nu, password) {
    const res = await _api('POST', '/api/register', { ...nu, password });
    _uid = res.uid;
    return _uid;
  }

  async function logout() {
    try { await _api('POST', '/api/logout'); } catch (e) { console.warn('[KasaDB] Logout error', e); }
    if (_uid) delete _mem['kt_d_' + _uid];
    delete _mem['kt_users'];
    _uid = null;
    clearTimeout(_writeTimer);
  }

  async function resetPw(newPassword) {
    await _api('POST', '/api/reset-password', { newPassword });
  }

  async function deleteAccount(password) {
    await _api('POST', '/api/delete-account', { password });
    if (_uid) delete _mem['kt_d_' + _uid];
    delete _mem['kt_users'];
    _uid = null;
    clearTimeout(_writeTimer);
  }

  /* ─── Profile ─── */
  async function updateProfile(fields) {
    if (!_uid) throw new Error('Oturum bulunamadı');
    await _api('PUT', '/api/profile', fields);
  }

  /* ─── Security Question / Forgot Password ─── */
  async function getSecurityQuestion(username) {
    const res = await _api('GET', '/api/security-question/' + encodeURIComponent(username));
    return res.question;
  }

  async function verifySecurityAnswer(username, answerRaw) {
    const normalized = answerRaw.trim().toLowerCase();
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest('SHA-256', enc.encode(normalized));
    const answerHash = 'sha256:' + Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    const res = await _api('POST', '/api/verify-security-answer', { username, answerHash });
    return res;
  }

  async function resetPwAnon(newPassword) {
    await _api('POST', '/api/reset-password-anon', { newPassword });
  }

  /* ─── Public Stats ─── */
  async function getPublicStats() {
    try { return await _api('GET', '/api/stats'); }
    catch (e) { console.warn('[KasaDB] getPublicStats error', e); return { users: 0, txns: 0, goals: 0 }; }
  }

  /* ─── Admin ─── */
  async function adminDeleteUser(uid) {
    await _api('POST', '/api/admin/delete', { uid });
    delete _mem['kt_d_' + uid];
    try {
      const users = JSON.parse(_mem['kt_users'] || '[]');
      _mem['kt_users'] = JSON.stringify(users.filter(u => u.uid !== uid));
    } catch (_) { }
  }

  async function adminSetBan(uid, isBanned, banReason = '') {
    await _api('POST', '/api/admin/ban', { uid, banned: isBanned, banReason });
    try {
      const users = JSON.parse(_mem['kt_users'] || '[]');
      const u = users.find(x => x.uid === uid);
      if (u) { u.banned = isBanned; u.banReason = banReason; }
      _mem['kt_users'] = JSON.stringify(users);
    } catch (_) { }
  }

  async function adminResetPassword(uid, newPassword) {
    await _api('POST', '/api/admin/reset-password', { uid, newPassword });
  }

  /* ─── Misc ─── */
  function flush() { return Promise.resolve(); }
  function keys() { return Object.keys(_mem); }
  function exportSnapshot() { return {}; }
  function importSnapshot() { return Promise.resolve(); }
  function stats() { return { keys: Object.keys(_mem).length }; }

  global.KasaDB = {
    init, getItem, setItem, removeItem, keys, flush, exportSnapshot, importSnapshot, stats,
    login, register, logout, resetPw, resetPwAnon, deleteAccount,
    updateProfile, verifySecurityAnswer, getSecurityQuestion,
    getPublicStats, adminDeleteUser, adminSetBan, adminResetPassword,
    _api,
    get uid() { return _uid; },
    get client() { return null; }
  };

})(window);