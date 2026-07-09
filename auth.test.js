/**
 * TEST SUITE: CRM Authentication — v6
 *
 * TDD mirror: các hàm dưới đây CHÉP LẠI logic thuần của apps-script-crm-v6.gs
 * để test được trên Node (GAS APIs không có sẵn). Giữ đồng bộ thủ công với .gs.
 *
 * Thay đổi so với v5:
 *  - hashPin(pin, salt) + lặp HASH_ITERS vòng; thêm hashPinLegacy(pin) (1 vòng)
 *  - login nâng cấp hash cũ (không salt) → salted khi đăng nhập đúng
 *  - setupPin(email, code, newPin, confirmPin): bắt buộc mã xác nhận; dùng cho
 *    cả setup lần đầu VÀ đặt lại khi quên (không còn "block lần 2")
 *  - requestSetupCode(email): phát mã, trả về THÔNG BÁO TRUNG TÍNH
 *  - changePin(email, oldPin, newPin, confirmPin): tự đổi PIN khi đã đăng nhập
 *  - BỎ setPin() của manager
 */

const crypto = require('crypto');

// Mock Utilities.computeDigest — hỗ trợ cả input chuỗi và mảng byte (như GAS)
const Utilities = {
  computeDigest: (algo, value) => {
    let buf;
    if (Array.isArray(value)) {
      buf = Buffer.from(value.map(b => (b < 0 ? b + 256 : b)));
    } else {
      buf = Buffer.from(String(value), 'utf8');
    }
    return [...crypto.createHash('sha256').update(buf).digest()];
  },
  getUuid: () => crypto.randomUUID(),
  DigestAlgorithm: { SHA_256: 'SHA_256' },
  Charset: { UTF_8: 'UTF_8' }
};

let authData = {};   // { email: { pinHash, salt, token, expiry, failCount, lockUntil, codeHash, codeExpiry, codeAttempts, codeIssuedAt } }
let lastSentCode = null; // giả lập "mã đã gửi qua email" để test đọc được

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const HASH_ITERS = 4096;
const SETUP_CODE_TTL_MS = 15 * 60 * 1000;
const SETUP_CODE_MAX_ATTEMPTS = 5;
const SETUP_CODE_COOLDOWN_MS = 60 * 1000;

const USERS = {
  'test@rsquare.vn':    { name: 'Test User',    role: 'staff',   disabled: false },
  'manager@rsquare.vn': { name: 'Test Manager', role: 'manager', disabled: false },
  'disabled@rsquare.vn':{ name: 'Old Staff',    role: 'staff',   disabled: true  },
};
function getDynamicUser(email) { return USERS[email] || null; }

/* ── hashing mirror ── */
function bytesToHex(bytes) {
  return bytes.map(b => ('0' + (b < 0 ? b + 256 : b).toString(16)).slice(-2)).join('');
}
function hashPin(pin, salt) {
  let raw = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(salt) + '|' + String(pin), Utilities.Charset.UTF_8);
  for (let i = 1; i < HASH_ITERS; i++) raw = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw);
  return bytesToHex(raw);
}
function hashPinLegacy(pin) {
  return bytesToHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(pin)));
}
function hashCode(code) {
  return bytesToHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, 'code|' + String(code)));
}
function makeSalt() {
  return (Utilities.getUuid() + Utilities.getUuid()).replace(/-/g, '');
}

/* ── login mirror (salt + legacy upgrade) ── */
function login(email, pin) {
  const u = getDynamicUser(email);
  if (!u) return { success: false, error: 'Email không có quyền truy cập' };
  if (u.disabled) return { success: false, error: 'Tài khoản đã bị vô hiệu hóa. Liên hệ quản lý.' };

  const record = authData[email] || {};
  const storedHash = record.pinHash || null;
  if (!storedHash) return { success: false, needsSetup: true, name: u.name };
  if (!pin || pin.length < 4) return { success: false, error: 'PIN không hợp lệ' };

  const now = Date.now();
  if (record.lockUntil && record.lockUntil > now) {
    const remaining = Math.ceil((record.lockUntil - now) / 60000);
    return { success: false, error: `Quá nhiều lần thử sai. Thử lại sau ${remaining} phút.` };
  }

  const salt = record.salt || '';
  let match, needUpgrade = false;
  if (salt) { match = (hashPin(pin, salt) === storedHash); }
  else { match = (hashPinLegacy(pin) === storedHash); needUpgrade = match; }

  if (!match) {
    const count = (record.failCount || 0) + 1;
    const lockUntil = count >= MAX_ATTEMPTS ? now + LOCKOUT_MS : (record.lockUntil || null);
    authData[email] = { ...record, failCount: count, lockUntil };
    const left = MAX_ATTEMPTS - count;
    if (left <= 0) return { success: false, error: `Sai PIN. Tài khoản bị tạm khóa 15 phút.` };
    return { success: false, error: `Sai PIN. Còn ${left} lần thử.` };
  }

  let upgraded = { ...record };
  if (needUpgrade) { const ns = makeSalt(); upgraded.pinHash = hashPin(pin, ns); upgraded.salt = ns; }

  const token = Utilities.getUuid();
  const expiry = now + SESSION_TTL_MS;
  authData[email] = { ...upgraded, token, expiry, failCount: 0, lockUntil: null };
  return { success: true, name: u.name, role: u.role, token, expiresAt: expiry };
}

/* ── requestSetupCode mirror ── */
function requestSetupCode(email) {
  const NEUTRAL = { success: true, message: 'Nếu email hợp lệ, mã xác nhận đã được gửi tới hộp thư đó.' };
  const u = getDynamicUser(email);
  if (!u || u.disabled) return NEUTRAL;

  const record = authData[email] || {};
  const now = Date.now();
  if (record.codeIssuedAt && (now - record.codeIssuedAt) < SETUP_CODE_COOLDOWN_MS) return NEUTRAL;

  const raw = parseInt(Utilities.getUuid().replace(/-/g, '').slice(0, 8), 16) % 1000000;
  const code = ('000000' + raw).slice(-6);
  authData[email] = { ...record, codeHash: hashCode(code), codeExpiry: now + SETUP_CODE_TTL_MS, codeAttempts: 0, codeIssuedAt: now };
  lastSentCode = code; // giả lập gửi mail
  return NEUTRAL;
}

/* ── setupPin mirror (code-verified; setup + reset) ── */
function setupPin(email, code, newPin, confirmPin) {
  const u = getDynamicUser(email);
  if (!u) return { success: false, error: 'Email không có quyền truy cập' };
  if (u.disabled) return { success: false, error: 'Tài khoản đã bị vô hiệu hóa' };
  if (!newPin || newPin.length < 4 || newPin.length > 8) return { success: false, error: 'PIN phải từ 4–8 chữ số' };
  if (!/^\d+$/.test(newPin)) return { success: false, error: 'PIN chỉ được chứa chữ số' };
  if (newPin !== confirmPin) return { success: false, error: 'PIN xác nhận không khớp' };
  if (!code) return { success: false, error: 'Vui lòng nhập mã xác nhận đã gửi tới email của bạn' };

  const record = authData[email] || {};
  const codeHash = record.codeHash || '';
  const exp = record.codeExpiry || 0;
  const attempts = record.codeAttempts || 0;

  if (!codeHash) return { success: false, error: 'Chưa có mã xác nhận. Bấm "Gửi mã" trước.' };
  if (Date.now() > exp) { authData[email] = { ...record, codeHash: '', codeExpiry: 0, codeAttempts: 0 }; return { success: false, error: 'Mã đã hết hạn. Vui lòng yêu cầu mã mới.' }; }
  if (attempts >= SETUP_CODE_MAX_ATTEMPTS) { authData[email] = { ...record, codeHash: '', codeExpiry: 0, codeAttempts: 0 }; return { success: false, error: 'Nhập sai mã quá nhiều lần. Vui lòng yêu cầu mã mới.' }; }

  if (hashCode(code) !== codeHash) {
    authData[email] = { ...record, codeAttempts: attempts + 1 };
    const left = SETUP_CODE_MAX_ATTEMPTS - (attempts + 1);
    return { success: false, error: `Mã xác nhận không đúng. Còn ${left} lần thử.` };
  }

  const salt = makeSalt();
  const token = Utilities.getUuid();
  const expiry = Date.now() + SESSION_TTL_MS;
  authData[email] = { pinHash: hashPin(newPin, salt), salt, token, expiry, failCount: 0, lockUntil: null };
  return { success: true, name: u.name, role: u.role, token, expiresAt: expiry };
}

/* ── changePin mirror (đã đăng nhập; cần PIN cũ) ── */
function changePin(email, oldPin, newPin, confirmPin) {
  if (!newPin || newPin.length < 4 || newPin.length > 8) return { success: false, error: 'PIN mới phải từ 4–8 chữ số' };
  if (!/^\d+$/.test(newPin)) return { success: false, error: 'PIN mới chỉ được chứa chữ số' };
  if (newPin !== confirmPin) return { success: false, error: 'PIN xác nhận không khớp' };

  const record = authData[email];
  if (!record || !record.pinHash) return { success: false, error: 'Tài khoản chưa đặt PIN' };
  const ok = record.salt ? (hashPin(oldPin, record.salt) === record.pinHash) : (hashPinLegacy(oldPin) === record.pinHash);
  if (!ok) return { success: false, error: 'PIN hiện tại không đúng' };
  if (newPin === oldPin) return { success: false, error: 'PIN mới phải khác PIN hiện tại' };

  const ns = makeSalt();
  authData[email] = { ...record, pinHash: hashPin(newPin, ns), salt: ns };
  return { success: true, message: 'Đổi PIN thành công' };
}

/* ── test helpers ── */
const TEST_SALT = 'fixedtestsalt';
function seed(email, pin, extra = {}) {
  authData[email] = { pinHash: hashPin(pin, TEST_SALT), salt: TEST_SALT, failCount: 0, ...extra };
}

/* ── runner ── */
let passed = 0, failed = 0, total = 0;
function test(d, fn) { total++; try { fn(); console.log(`  ✅ ${d}`); passed++; } catch (e) { console.log(`  ❌ ${d}`); console.log(`     → ${e.message}`); failed++; } }
function expect(actual) {
  return {
    toBe: (e) => { if (actual !== e) throw new Error(`Expected ${JSON.stringify(e)}, got ${JSON.stringify(actual)}`); },
    toContain: (e) => { if (!String(actual).includes(e)) throw new Error(`Expected "${actual}" to contain "${e}"`); },
    toBeTruthy: () => { if (!actual) throw new Error(`Expected truthy, got ${JSON.stringify(actual)}`); },
    toBeFalsy: () => { if (actual) throw new Error(`Expected falsy, got ${JSON.stringify(actual)}`); },
    toBeGreaterThan: (n) => { if (actual <= n) throw new Error(`Expected ${actual} > ${n}`); },
    notToBe: (e) => { if (actual === e) throw new Error(`Expected NOT ${JSON.stringify(e)}`); }
  };
}

// ════ Suite 1: hashing (H2) ════
console.log('\n📋 Suite 1: hashPin() có salt + hashPinLegacy()');
test('cùng pin + cùng salt → hash giống (deterministic)', () => { expect(hashPin('1234', 's')).toBe(hashPin('1234', 's')); });
test('cùng pin, salt khác → hash KHÁC nhau', () => { if (hashPin('1234', 'a') === hashPin('1234', 'b')) throw new Error('salt phải làm khác hash'); });
test('pin khác → hash khác', () => { if (hashPin('1234', 's') === hashPin('5678', 's')) throw new Error('x'); });
test('hash 64 hex', () => { expect(hashPin('123456', 's').length).toBe(64); });
test('hash không chứa pin gốc', () => { if (hashPin('123456', 's').includes('123456')) throw new Error('x'); });
test('salted khác legacy (đảm bảo nâng cấp có tác dụng)', () => { if (hashPin('1234', 's') === hashPinLegacy('1234')) throw new Error('x'); });

// ════ Suite 2: login email ════
console.log('\n📋 Suite 2: login() — email validation');
test('email lạ', () => { const r = login('unknown@rsquare.vn', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('quyền truy cập'); });
test('disabled', () => { const r = login('disabled@rsquare.vn', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('vô hiệu hóa'); });

// ════ Suite 3: needsSetup ════
console.log('\n📋 Suite 3: login() — PIN chưa set');
authData = {};
test('needsSetup true', () => { const r = login('test@rsquare.vn', ''); expect(r.needsSetup).toBe(true); expect(r.success).toBe(false); });
test('needsSetup có name', () => { const r = login('test@rsquare.vn', ''); expect(r.name).toBe('Test User'); });

// ════ Suite 4: PIN verify ════
console.log('\n📋 Suite 4: login() — PIN verification (salted)');
test('PIN đúng → có token', () => { authData = {}; seed('test@rsquare.vn', '1234'); const r = login('test@rsquare.vn', '1234'); expect(r.success).toBe(true); expect(r.token).toBeTruthy(); });
test('role staff', () => { authData = {}; seed('test@rsquare.vn', '1234'); expect(login('test@rsquare.vn', '1234').role).toBe('staff'); });
test('role manager', () => { authData = {}; seed('manager@rsquare.vn', '9999'); expect(login('manager@rsquare.vn', '9999').role).toBe('manager'); });
test('PIN sai → lỗi', () => { authData = {}; seed('test@rsquare.vn', '1234'); const r = login('test@rsquare.vn', '9999'); expect(r.success).toBe(false); expect(r.error).toContain('Sai PIN'); });
test('expiry 8h', () => { authData = {}; seed('test@rsquare.vn', '1234'); const r = login('test@rsquare.vn', '1234'); expect(r.expiresAt).toBeGreaterThan(Date.now() + 8 * 60 * 60 * 1000 - 1000); });

// ════ Suite 5: rate limit ════
console.log('\n📋 Suite 5: rate limiting — 5 sai → lock');
authData = {}; seed('test@rsquare.vn', '1234');
test('sai1 còn4', () => { expect(login('test@rsquare.vn', 'wrong').error).toContain('Còn 4 lần thử'); });
test('sai2 còn3', () => { expect(login('test@rsquare.vn', 'wrong').error).toContain('Còn 3 lần thử'); });
test('sai3 còn2', () => { expect(login('test@rsquare.vn', 'wrong').error).toContain('Còn 2 lần thử'); });
test('sai4 còn1', () => { expect(login('test@rsquare.vn', 'wrong').error).toContain('Còn 1 lần thử'); });
test('sai5 lock', () => { const r = login('test@rsquare.vn', 'wrong'); expect(r.success).toBe(false); expect(r.error).toContain('tạm khóa'); });
test('locked dù đúng PIN', () => { const r = login('test@rsquare.vn', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('phút'); });

// ════ Suite 6: requestSetupCode (H1) ════
console.log('\n📋 Suite 6: requestSetupCode() — phát mã');
test('email hợp lệ → phát mã 6 số', () => { authData = {}; lastSentCode = null; requestSetupCode('test@rsquare.vn'); expect(String(lastSentCode).length).toBe(6); });
test('trả về thông báo trung tính', () => { authData = {}; const r = requestSetupCode('test@rsquare.vn'); expect(r.success).toBe(true); expect(r.message).toContain('Nếu email hợp lệ'); });
test('email lạ → KHÔNG phát mã, vẫn trung tính', () => { authData = {}; lastSentCode = null; const r = requestSetupCode('nobody@rsquare.vn'); expect(r.success).toBe(true); expect(lastSentCode).toBeFalsy(); });
test('disabled → KHÔNG phát mã', () => { authData = {}; lastSentCode = null; requestSetupCode('disabled@rsquare.vn'); expect(lastSentCode).toBeFalsy(); });
test('cooldown → không phát lại ngay', () => {
  authData = {}; lastSentCode = null;
  requestSetupCode('test@rsquare.vn'); const first = lastSentCode;
  lastSentCode = null; requestSetupCode('test@rsquare.vn'); // trong 60s
  expect(lastSentCode).toBeFalsy(); expect(String(first).length).toBe(6);
});

// ════ Suite 7: setupPin qua mã (H1) ════
console.log('\n📋 Suite 7: setupPin() — bắt buộc mã xác nhận');
test('mã đúng → set PIN + login ngay', () => { authData = {}; requestSetupCode('test@rsquare.vn'); const r = setupPin('test@rsquare.vn', lastSentCode, '1234', '1234'); expect(r.success).toBe(true); expect(r.token).toBeTruthy(); });
test('không có mã trong hệ thống → chặn', () => { authData = {}; const r = setupPin('test@rsquare.vn', '000000', '1234', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('Chưa có mã'); });
test('mã sai → chặn', () => { authData = {}; requestSetupCode('test@rsquare.vn'); const bad = lastSentCode === '111111' ? '222222' : '111111'; const r = setupPin('test@rsquare.vn', bad, '1234', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('không đúng'); });
test('mã hết hạn → chặn', () => { authData = {}; requestSetupCode('test@rsquare.vn'); const code = lastSentCode; authData['test@rsquare.vn'].codeExpiry = Date.now() - 1000; const r = setupPin('test@rsquare.vn', code, '1234', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('hết hạn'); });
test('nhập sai mã quá nhiều → chặn (guard)', () => { authData = {}; requestSetupCode('test@rsquare.vn'); const code = lastSentCode; authData['test@rsquare.vn'].codeAttempts = SETUP_CODE_MAX_ATTEMPTS; const r = setupPin('test@rsquare.vn', code, '1234', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('quá nhiều'); });
test('thiếu mã → nhắc nhập mã', () => { authData = {}; requestSetupCode('test@rsquare.vn'); const r = setupPin('test@rsquare.vn', '', '1234', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('mã xác nhận'); });
test('PIN<4 → validation trước cả mã', () => { authData = {}; const r = setupPin('test@rsquare.vn', '123456', '123', '123'); expect(r.success).toBe(false); expect(r.error).toContain('4–8'); });
test('PIN chữ → validation', () => { authData = {}; const r = setupPin('test@rsquare.vn', '123456', 'abc1', 'abc1'); expect(r.success).toBe(false); expect(r.error).toContain('chữ số'); });
test('không khớp → validation', () => { authData = {}; const r = setupPin('test@rsquare.vn', '123456', '1234', '5678'); expect(r.success).toBe(false); expect(r.error).toContain('không khớp'); });
test('disabled không setup được', () => { authData = {}; const r = setupPin('disabled@rsquare.vn', '123456', '1234', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('vô hiệu hóa'); });

// ════ Suite 8: reset qua mã (thay cho "block lần 2" của v5) ════
console.log('\n📋 Suite 8: quên PIN → đặt lại qua mã');
test('user ĐÃ có PIN vẫn reset được bằng mã mới', () => {
  authData = {}; seed('test@rsquare.vn', '1111');
  requestSetupCode('test@rsquare.vn');
  const r = setupPin('test@rsquare.vn', lastSentCode, '2222', '2222');
  expect(r.success).toBe(true);
});
test('sau reset, PIN cũ KHÔNG dùng được', () => {
  authData = {}; seed('test@rsquare.vn', '1111');
  requestSetupCode('test@rsquare.vn'); setupPin('test@rsquare.vn', lastSentCode, '2222', '2222');
  const r = login('test@rsquare.vn', '1111'); expect(r.success).toBe(false);
});
test('sau reset, PIN mới dùng được', () => {
  authData = {}; seed('test@rsquare.vn', '1111');
  requestSetupCode('test@rsquare.vn'); setupPin('test@rsquare.vn', lastSentCode, '2222', '2222');
  const r = login('test@rsquare.vn', '2222'); expect(r.success).toBe(true);
});

// ════ Suite 9: changePin ════
console.log('\n📋 Suite 9: changePin() — tự đổi khi đã đăng nhập');
test('PIN cũ đúng → đổi thành công', () => { authData = {}; seed('test@rsquare.vn', '1234'); const r = changePin('test@rsquare.vn', '1234', '5678', '5678'); expect(r.success).toBe(true); });
test('sau đổi, PIN mới login được', () => { authData = {}; seed('test@rsquare.vn', '1234'); changePin('test@rsquare.vn', '1234', '5678', '5678'); expect(login('test@rsquare.vn', '5678').success).toBe(true); });
test('sau đổi, PIN cũ KHÔNG login được', () => { authData = {}; seed('test@rsquare.vn', '1234'); changePin('test@rsquare.vn', '1234', '5678', '5678'); expect(login('test@rsquare.vn', '1234').success).toBe(false); });
test('PIN cũ sai → chặn', () => { authData = {}; seed('test@rsquare.vn', '1234'); const r = changePin('test@rsquare.vn', '0000', '5678', '5678'); expect(r.success).toBe(false); expect(r.error).toContain('hiện tại không đúng'); });
test('PIN mới = PIN cũ → chặn', () => { authData = {}; seed('test@rsquare.vn', '1234'); const r = changePin('test@rsquare.vn', '1234', '1234', '1234'); expect(r.success).toBe(false); expect(r.error).toContain('khác PIN hiện tại'); });
test('PIN mới không khớp confirm → chặn', () => { authData = {}; seed('test@rsquare.vn', '1234'); const r = changePin('test@rsquare.vn', '1234', '5678', '9999'); expect(r.success).toBe(false); expect(r.error).toContain('không khớp'); });

// ════ Suite 10: nâng cấp hash cũ (H2 migration) ════
console.log('\n📋 Suite 10: nâng cấp hash legacy → salted khi login');
test('hash cũ (không salt) + PIN đúng → login được', () => { authData = { 'test@rsquare.vn': { pinHash: hashPinLegacy('1234'), failCount: 0 } }; const r = login('test@rsquare.vn', '1234'); expect(r.success).toBe(true); });
test('sau login, record có salt (đã nâng cấp)', () => { authData = { 'test@rsquare.vn': { pinHash: hashPinLegacy('1234'), failCount: 0 } }; login('test@rsquare.vn', '1234'); expect(authData['test@rsquare.vn'].salt).toBeTruthy(); });
test('sau nâng cấp, hash mới = salted hash', () => { authData = { 'test@rsquare.vn': { pinHash: hashPinLegacy('1234'), failCount: 0 } }; login('test@rsquare.vn', '1234'); const rec = authData['test@rsquare.vn']; expect(rec.pinHash).toBe(hashPin('1234', rec.salt)); });
test('hash cũ + PIN sai → vẫn chặn (không nâng cấp nhầm)', () => { authData = { 'test@rsquare.vn': { pinHash: hashPinLegacy('1234'), failCount: 0 } }; const r = login('test@rsquare.vn', '9999'); expect(r.success).toBe(false); expect(authData['test@rsquare.vn'].salt).toBeFalsy(); });

// ════ RESULTS ════
console.log('\n' + '─'.repeat(50));
console.log(`Results: ${passed}/${total} passed, ${failed} failed`);
if (failed === 0) { console.log('🎉 ALL TESTS PASSED — safe to deploy'); }
else { console.log('🚫 TESTS FAILED — fix before deploy'); process.exit(1); }
