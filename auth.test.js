/**
 * TEST SUITE: CRM Authentication
 * 
 * TDD flow: Những test này được viết TRƯỚC khi implement
 * Mục tiêu: mô tả chính xác hàm cần làm gì
 */

// ─── Mock environment (giả lập Google Apps Script) ────────────────
// Vì GAS không chạy được trên Node.js, ta cần mock các hàm GAS
const crypto = require('crypto');

// Mock Utilities.computeDigest (GAS built-in)
const Utilities = {
  computeDigest: (algo, str) => {
    return [...crypto.createHash('sha256').update(str).digest()];
  },
  getUuid: () => crypto.randomUUID(),
  DigestAlgorithm: { SHA_256: 'SHA_256' }
};

// Mock SpreadsheetApp + in-memory _AUTH sheet
let authData = {}; // { email: { pinHash, token, expiry, failCount, lockUntil } }

// ─── Load business logic từ GS ────────────────────────────────────
// Extract các hàm pure (không phụ thuộc GAS) để test được
function hashPin(pin) {
  const bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, String(pin)
  );
  return bytes.map(b => ('0' + (b < 0 ? b + 256 : b).toString(16)).slice(-2)).join('');
}

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

const USERS = {
  'test@rsquare.vn':    { name: 'Test User',   role: 'staff',   disabled: false },
  'manager@rsquare.vn': { name: 'Test Manager', role: 'manager', disabled: false },
  'disabled@rsquare.vn':{ name: 'Old Staff',    role: 'staff',   disabled: true  },
};

function getDynamicUser(email) {
  return USERS[email] || null;
}

// Simplified in-memory version của login logic (mirror GS)
function login(email, pin) {
  const u = getDynamicUser(email);
  if (!u) return { success: false, error: 'Email không có quyền truy cập' };
  if (u.disabled) return { success: false, error: 'Tài khoản đã bị vô hiệu hóa. Liên hệ quản lý.' };

  const record = authData[email] || {};
  const storedHash = record.pinHash || null;

  // PIN chưa được set
  if (!storedHash) return { success: false, needsSetup: true, name: u.name };

  if (!pin || pin.length < 4) return { success: false, error: 'PIN không hợp lệ' };

  // Rate limiting
  const now = Date.now();
  if (record.lockUntil && record.lockUntil > now) {
    const remaining = Math.ceil((record.lockUntil - now) / 60000);
    return { success: false, error: `Quá nhiều lần thử sai. Thử lại sau ${remaining} phút.` };
  }

  // Verify PIN
  if (hashPin(pin) !== storedHash) {
    const count = (record.failCount || 0) + 1;
    const lockUntil = count >= MAX_ATTEMPTS ? now + LOCKOUT_MS : (record.lockUntil || null);
    authData[email] = { ...record, failCount: count, lockUntil };
    const left = MAX_ATTEMPTS - count;
    if (left <= 0) return { success: false, error: `Sai PIN. Tài khoản bị tạm khóa 15 phút.` };
    return { success: false, error: `Sai PIN. Còn ${left} lần thử.` };
  }

  // Success
  const token = Utilities.getUuid();
  const expiry = now + SESSION_TTL_MS;
  authData[email] = { ...record, pinHash: storedHash, token, expiry, failCount: 0, lockUntil: null };
  return { success: true, name: u.name, role: u.role, token, expiresAt: expiry };
}

function setupPin(email, newPin, confirmPin) {
  const u = getDynamicUser(email);
  if (!u) return { success: false, error: 'Email không có quyền truy cập' };
  if (u.disabled) return { success: false, error: 'Tài khoản đã bị vô hiệu hóa' };
  if (!newPin || newPin.length < 4 || newPin.length > 8)
    return { success: false, error: 'PIN phải từ 4–8 chữ số' };
  if (!/^\d+$/.test(newPin))
    return { success: false, error: 'PIN chỉ được chứa chữ số' };
  if (newPin !== confirmPin)
    return { success: false, error: 'PIN xác nhận không khớp' };
  const record = authData[email] || {};
  if (record.pinHash)
    return { success: false, error: 'PIN đã được thiết lập. Liên hệ quản lý nếu cần đặt lại.' };
  const token = Utilities.getUuid();
  const expiry = Date.now() + SESSION_TTL_MS;
  authData[email] = { pinHash: hashPin(newPin), token, expiry, failCount: 0 };
  return { success: true, name: u.name, role: u.role, token, expiresAt: expiry };
}

// ─── TEST RUNNER (không dùng library, viết tay để học rõ) ─────────
let passed = 0, failed = 0, total = 0;

function test(description, fn) {
  total++;
  try {
    fn();
    console.log(`  ✅ ${description}`);
    passed++;
  } catch(e) {
    console.log(`  ❌ ${description}`);
    console.log(`     → ${e.message}`);
    failed++;
  }
}

function expect(actual) {
  return {
    toBe: (expected) => {
      if (actual !== expected)
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    },
    toContain: (expected) => {
      if (!String(actual).includes(expected))
        throw new Error(`Expected "${actual}" to contain "${expected}"`);
    },
    toBeTruthy: () => {
      if (!actual) throw new Error(`Expected truthy, got ${JSON.stringify(actual)}`);
    },
    toBeFalsy: () => {
      if (actual) throw new Error(`Expected falsy, got ${JSON.stringify(actual)}`);
    },
    toBeGreaterThan: (n) => {
      if (actual <= n) throw new Error(`Expected ${actual} > ${n}`);
    }
  };
}

function beforeEach(fn) { return fn; } // helper for readability

// ════════════════════════════════════════════════════════════════
// TEST SUITE 1: hashPin
// ════════════════════════════════════════════════════════════════
console.log('\n📋 Suite 1: hashPin()');

test('PIN giống nhau → hash giống nhau (deterministic)', () => {
  expect(hashPin('1234')).toBe(hashPin('1234'));
});

test('PIN khác nhau → hash khác nhau', () => {
  if (hashPin('1234') === hashPin('5678'))
    throw new Error('Different PINs should produce different hashes');
});

test('Hash luôn là 64 ký tự hex (SHA-256)', () => {
  expect(hashPin('123456').length).toBe(64);
});

test('Hash không chứa PIN gốc (không lưu plain text)', () => {
  if (hashPin('123456').includes('123456'))
    throw new Error('Hash should not contain original PIN');
});

// ════════════════════════════════════════════════════════════════
// TEST SUITE 2: login() — email validation
// ════════════════════════════════════════════════════════════════
console.log('\n📋 Suite 2: login() — Email validation');

test('Email không tồn tại → lỗi "không có quyền"', () => {
  const result = login('unknown@rsquare.vn', '1234');
  expect(result.success).toBe(false);
  expect(result.error).toContain('quyền truy cập');
});

test('Tài khoản disabled → lỗi "bị vô hiệu hóa"', () => {
  const result = login('disabled@rsquare.vn', '1234');
  expect(result.success).toBe(false);
  expect(result.error).toContain('vô hiệu hóa');
});

// ════════════════════════════════════════════════════════════════
// TEST SUITE 3: login() — First time setup
// ════════════════════════════════════════════════════════════════
console.log('\n📋 Suite 3: login() — PIN chưa được set');

// Reset auth state
authData = {};

test('Login khi chưa có PIN → trả về needsSetup: true', () => {
  const result = login('test@rsquare.vn', '');
  expect(result.needsSetup).toBe(true);
  expect(result.success).toBe(false);
});

test('needsSetup response có chứa name để hiển thị welcome', () => {
  const result = login('test@rsquare.vn', '');
  expect(result.name).toBe('Test User');
});

// ════════════════════════════════════════════════════════════════
// TEST SUITE 4: login() — PIN verification
// ════════════════════════════════════════════════════════════════
console.log('\n📋 Suite 4: login() — PIN verification');

// Setup: đặt PIN cho test user
authData = { 'test@rsquare.vn': { pinHash: hashPin('1234'), failCount: 0 } };

test('PIN đúng → login thành công, có token', () => {
  const result = login('test@rsquare.vn', '1234');
  expect(result.success).toBe(true);
  expect(result.token).toBeTruthy();
});

test('PIN đúng → role trả về đúng', () => {
  authData = { 'test@rsquare.vn': { pinHash: hashPin('1234'), failCount: 0 } };
  const result = login('test@rsquare.vn', '1234');
  expect(result.role).toBe('staff');
});

test('Manager login đúng → role = manager', () => {
  authData = { 'manager@rsquare.vn': { pinHash: hashPin('9999'), failCount: 0 } };
  const result = login('manager@rsquare.vn', '9999');
  expect(result.role).toBe('manager');
});

test('PIN sai → lỗi, còn N lần thử', () => {
  authData = { 'test@rsquare.vn': { pinHash: hashPin('1234'), failCount: 0 } };
  const result = login('test@rsquare.vn', '9999');
  expect(result.success).toBe(false);
  expect(result.error).toContain('Sai PIN');
});

test('Session token có expiry 8 giờ trong tương lai', () => {
  authData = { 'test@rsquare.vn': { pinHash: hashPin('1234'), failCount: 0 } };
  const result = login('test@rsquare.vn', '1234');
  const eightHoursMs = 8 * 60 * 60 * 1000;
  expect(result.expiresAt).toBeGreaterThan(Date.now() + eightHoursMs - 1000);
});

// ════════════════════════════════════════════════════════════════
// TEST SUITE 5: Rate Limiting — QUAN TRỌNG nhất về security
// ════════════════════════════════════════════════════════════════
console.log('\n📋 Suite 5: Rate limiting — 5 lần sai → lock 15 phút');

authData = { 'test@rsquare.vn': { pinHash: hashPin('1234'), failCount: 0 } };

test('Sai 1 lần → còn 4 lần thử', () => {
  const r = login('test@rsquare.vn', 'wrong');
  expect(r.error).toContain('Còn 4 lần thử');
});

test('Sai 2 lần → còn 3 lần thử', () => {
  const r = login('test@rsquare.vn', 'wrong');
  expect(r.error).toContain('Còn 3 lần thử');
});

test('Sai 3 lần → còn 2 lần thử', () => {
  const r = login('test@rsquare.vn', 'wrong');
  expect(r.error).toContain('Còn 2 lần thử');
});

test('Sai 4 lần → còn 1 lần thử', () => {
  const r = login('test@rsquare.vn', 'wrong');
  expect(r.error).toContain('Còn 1 lần thử');
});

test('Sai lần thứ 5 → bị lock, không còn lần thử nào', () => {
  const r = login('test@rsquare.vn', 'wrong');
  expect(r.success).toBe(false);
  expect(r.error).toContain('tạm khóa');
});

test('Sau khi bị lock, dù nhập PIN đúng vẫn không vào được', () => {
  const r = login('test@rsquare.vn', '1234'); // đúng PIN nhưng bị lock
  expect(r.success).toBe(false);
  expect(r.error).toContain('phút');
});

// ════════════════════════════════════════════════════════════════
// TEST SUITE 6: setupPin() — Self-service
// ════════════════════════════════════════════════════════════════
console.log('\n📋 Suite 6: setupPin() — Tự đặt PIN lần đầu');

authData = {}; // Reset — chưa ai có PIN

test('Setup PIN hợp lệ lần đầu → thành công + login ngay', () => {
  const r = setupPin('test@rsquare.vn', '1234', '1234');
  expect(r.success).toBe(true);
  expect(r.token).toBeTruthy();
});

test('Setup PIN lần 2 → bị block (guard hoạt động)', () => {
  // authData['test@rsquare.vn'] đã có PIN từ test trên
  const r = setupPin('test@rsquare.vn', '5678', '5678');
  expect(r.success).toBe(false);
  expect(r.error).toContain('đã được thiết lập');
});

test('PIN < 4 số → lỗi validation', () => {
  authData = {};
  const r = setupPin('test@rsquare.vn', '123', '123');
  expect(r.success).toBe(false);
  expect(r.error).toContain('4–8');
});

test('PIN chứa chữ cái → lỗi validation', () => {
  authData = {};
  const r = setupPin('test@rsquare.vn', 'abc1', 'abc1');
  expect(r.success).toBe(false);
  expect(r.error).toContain('chữ số');
});

test('PIN xác nhận không khớp → lỗi', () => {
  authData = {};
  const r = setupPin('test@rsquare.vn', '1234', '5678');
  expect(r.success).toBe(false);
  expect(r.error).toContain('không khớp');
});

test('Disabled user không setup được PIN', () => {
  authData = {};
  const r = setupPin('disabled@rsquare.vn', '1234', '1234');
  expect(r.success).toBe(false);
  expect(r.error).toContain('vô hiệu hóa');
});

// ════════════════════════════════════════════════════════════════
// RESULTS
// ════════════════════════════════════════════════════════════════
console.log('\n' + '─'.repeat(50));
console.log(`Results: ${passed}/${total} passed, ${failed} failed`);
if (failed === 0) {
  console.log('🎉 ALL TESTS PASSED — safe to deploy');
} else {
  console.log('🚫 TESTS FAILED — fix before deploy');
  process.exit(1);
}
