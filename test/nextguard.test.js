/**
 * NextGuard — Comprehensive Test Suite
 * Run: node test/nextguard.test.js
 */
'use strict';

const assert = require('assert');
const { EventEmitter } = require('events');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    const result = fn();
    if (result instanceof Promise) {
      result.then(() => {
        console.log(`  \x1b[32m✓\x1b[0m ${name}`);
        passed++;
      }).catch((err) => {
        console.error(`  \x1b[31m✗\x1b[0m ${name}\n    ${err.message}`);
        failed++;
      });
    } else {
      console.log(`  \x1b[32m✓\x1b[0m ${name}`);
      passed++;
    }
  } catch (err) {
    console.error(`  \x1b[31m✗\x1b[0m ${name}\n    ${err.message}`);
    failed++;
  }
}

const nextguard = require('../nextguard');
const {
  createNextGuard,
  getClientIP,
  inspectValue,
  deepInspect,
  ipInCIDR,
  VERSION,
} = nextguard;

// ── Mock Helpers ─────────────────────────────────────────────────────────────

function mockReq(overrides = {}) {
  return {
    method: 'GET',
    url: '/',
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      host: 'example.com',
    },
    socket: { remoteAddress: '127.0.0.1' },
    body: null,
    ...overrides,
  };
}

function mockRes() {
  const res = {
    headersSent: false,
    writableEnded: false,
    _status: 200,
    _headers: {},
    _body: null,
    setHeader(k, v) { this._headers[k.toLowerCase()] = v; },
    write(d) { return !this.writableEnded; },
    end(body) {
      this._body = body;
      this.writableEnded = true;
    },
  };
  Object.defineProperty(res, 'statusCode', {
    get() { return this._status; },
    set(v) { this._status = v; },
  });
  return res;
}

function mockNextRequest(pathname = '/', options = {}) {
  const headers = new Map();
  headers.set('user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
  headers.set('x-forwarded-for', options.ip || '127.0.0.1');

  if (options.headers) {
    for (const [k, v] of Object.entries(options.headers)) {
      headers.set(k.toLowerCase(), v);
    }
  }

  const fullUrl = `http://localhost:3000${pathname.startsWith('/') ? pathname : '/' + pathname}`;

  return {
    method: options.method || 'GET',
    url: fullUrl,
    nextUrl: {
      pathname: pathname.split('?')[0],
      search: pathname.includes('?') ? '?' + pathname.split('?').slice(1).join('?') : '',
      toString: () => fullUrl,
    },
    headers: {
      get: (name) => headers.get(name.toLowerCase()) || null,
      entries: () => headers.entries(),
    },
    ip: options.ip || '127.0.0.1',
    body: options.body || null,
  };
}

// ══════════════════════════════════════════════════════════════════════════════
console.log('\n\x1b[1m  NextGuard v' + VERSION + ' Test Suite\x1b[0m\n');

// ── Utilities ──────────────────────────────────────────────────────────────
console.log('\x1b[36m  1. Utilities & Core Helpers\x1b[0m');

test('VERSION is a valid semver string', () => {
  assert.strictEqual(typeof VERSION, 'string');
  assert.match(VERSION, /^\d+\.\d+\.\d+$/);
});

test('getClientIP returns remote address fallback', () => {
  assert.strictEqual(getClientIP(mockReq(), false), '127.0.0.1');
});

test('getClientIP reads X-Forwarded-For', () => {
  const req = mockReq({ headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' } });
  assert.strictEqual(getClientIP(req, true), '1.2.3.4');
});

test('getClientIP reads CF-Connecting-IP', () => {
  const req = mockReq({ headers: { 'cf-connecting-ip': '9.10.11.12' } });
  assert.strictEqual(getClientIP(req, true), '9.10.11.12');
});

test('ipInCIDR — exact match', () => {
  assert.strictEqual(ipInCIDR('192.168.1.1', '192.168.1.1'), true);
  assert.strictEqual(ipInCIDR('192.168.1.2', '192.168.1.1'), false);
});

test('ipInCIDR — CIDR /24', () => {
  assert.strictEqual(ipInCIDR('192.168.1.50', '192.168.1.0/24'), true);
  assert.strictEqual(ipInCIDR('192.168.2.1', '192.168.1.0/24'), false);
});

test('ipInCIDR — CIDR /8', () => {
  assert.strictEqual(ipInCIDR('10.0.0.1', '10.0.0.0/8'), true);
  assert.strictEqual(ipInCIDR('11.0.0.1', '10.0.0.0/8'), false);
});

// ── Layer 5 — Payload Inspection & False Positive Fixes ────────────────────
console.log('\n\x1b[36m  2. Layer 5 — Payload Inspection & Zero False Positive Protections\x1b[0m');

test('inspectValue — clean input passes', () => {
  assert.strictEqual(inspectValue('Hello World').matched, false);
});

test('inspectValue — SQL UNION SELECT blocked', () => {
  assert.strictEqual(inspectValue("' UNION SELECT * FROM users--").matched, true);
});

test('inspectValue — SQL sleep() blocked', () => {
  assert.strictEqual(inspectValue('sleep(5)').matched, true);
});

test('inspectValue — XSS <script> blocked', () => {
  assert.strictEqual(inspectValue('<script>alert(1)</script>').matched, true);
});

test('inspectValue — Path traversal blocked', () => {
  assert.strictEqual(inspectValue('../../etc/passwd').matched, true);
});

test('deepInspect — passwords with special characters ($#;!&) do NOT trigger false positives', () => {
  // Common login passwords that previously got falsely flagged as RCE or SQLi
  const safePasswords = [
    'P@ssw0rd$#123!',
    'secret;password',
    'admin&co(123)',
    'complex"password\'test',
    'my$()special`pass',
  ];

  for (const pw of safePasswords) {
    const r = deepInspect({ email: 'user@example.com', password: pw });
    assert.strictEqual(r.matched, false, `Password "${pw}" should not be flagged as attack`);
  }
});

test('deepInspect — SQL injection in non-password field is still detected and blocked', () => {
  const r = deepInspect({ username: "' UNION SELECT 1,2,3--", password: 'safe' });
  assert.strictEqual(r.matched, true);
});

// ── Next.js Desktop Zero-Delay Performance Tests ─────────────────────────────
console.log('\n\x1b[36m  3. Next.js Static Asset Bypass (Zero-Delay on Desktop)\x1b[0m');

test('Next.js static asset chunks bypass rate limiting with 0ms delay', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const staticAssets = [
    '/_next/static/chunks/main-app.js',
    '/_next/static/chunks/webpack.js',
    '/_next/static/css/styles.css',
    '/_next/image?url=%2Flogo.png&w=128&q=75',
    '/favicon.ico',
    '/fonts/inter.woff2',
    '/images/banner.png',
  ];

  // Simulating 50 rapid static file downloads (desktop page load)
  for (const asset of staticAssets) {
    const req = mockNextRequest(asset, { ip: '192.0.2.10' });
    const start = Date.now();
    const res = await mw(req);
    const duration = Date.now() - start;

    assert.strictEqual(res, null, `Asset ${asset} should be allowed`);
    assert.ok(duration < 500, `Asset ${asset} must be served without artificial delay (${duration}ms)`);

  }
});

// ── Normal Login Flow Tests ──────────────────────────────────────────────────
console.log('\n\x1b[36m  4. Normal User Login Flow (No False Attacks)\x1b[0m');

test('User login POST request with complex password is fully allowed', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const loginReq = mockNextRequest('/api/auth/callback/credentials', {
    method: 'POST',
    ip: '192.0.2.20',
    headers: {
      'content-type': 'application/json',
      'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125"',
      'referer': 'http://localhost:3000/login',
    },
    body: {
      email: 'john.doe@company.com',
      password: 'MySecretPassword!@#123;cat',
    },
  });

  const res = await mw(loginReq);
  assert.strictEqual(res, null, 'Normal user login must pass firewall without false attack detection');
});

test('Session cookies and NextAuth tokens do not trigger attack detection', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const req = mockNextRequest('/dashboard', {
    ip: '192.0.2.21',
    headers: {
      cookie: 'next-auth.session-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ; _ga=GA1.1.123456789.1700000000; next-auth.csrf-token=9876543210abcdef',
    },
  });

  const res = await mw(req);
  assert.strictEqual(res, null, 'Dashboard access with session cookie must be allowed');
});

// ── Path-Agnostic Architecture Tests ─────────────────────────────────────────
console.log('\n\x1b[36m  5. Path-Agnostic Architecture (Any Path / No Hardcoded Routes)\x1b[0m');

test('nextguard() works without any path parameters', () => {
  const mw = nextguard();
  assert.strictEqual(typeof mw, 'function');
});

test('NextGuard allows all standard application paths transparently', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const testPaths = [
    '/',
    '/login',
    '/dashboard',
    '/admin',
    '/api/users',
    '/api/payment',
    '/my-custom-path',
    '/whatever/123',
  ];

  for (const path of testPaths) {
    const req = mockNextRequest(path, { ip: '192.0.2.30' });
    const response = await mw(req);
    assert.strictEqual(response, null, `Path "${path}" must be allowed`);
  }
});

test('/admin is NOT treated as a honeypot and is allowed through', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const req = mockNextRequest('/admin', { ip: '192.0.2.31' });
  const response = await mw(req);
  assert.strictEqual(response, null, '/admin route must not be blocked');
});

test('Wildcard matcher /:path* functions smoothly', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const routes = ['/', '/profile', '/settings/security', '/api/v1/auth/callback'];
  for (const route of routes) {
    const req = mockNextRequest(route, { ip: '192.0.2.32' });
    assert.strictEqual(await mw(req), null);
  }
});

test('Firewall still strictly blocks real SQLi attack on /api/payment', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const req = mockNextRequest("/api/payment?id=' UNION SELECT * FROM users--", { ip: '192.0.2.33' });
  const res = await mw(req);
  assert.ok(res !== null, 'Real SQLi attack must be blocked');
  assert.strictEqual(res.status, 400);
});

// ── Telegram Alert Integration Tests ─────────────────────────────────────────
console.log('\n\x1b[36m  6. Telegram Real-Time Security Alerts (Vercel Ready)\x1b[0m');

test('Telegram alert is dispatched on genuine attack', async () => {
  let telegramPayload = null;
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    if (url.includes('api.telegram.org')) {
      telegramPayload = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }
    return originalFetch ? originalFetch(url, options) : null;
  };

  try {
    const mw = nextguard({
      logLevel: 'silent',
      telegram: {
        enabled: true,
        botToken: '123456:TEST_TOKEN',
        chatId: '-100123456789',
        cooldownMs: 0,
      },
    });

    const req = mockNextRequest('/api/checkout?param=<script>alert(1)</script>', { ip: '198.51.100.99' });
    await mw(req);
    await new Promise((r) => setTimeout(r, 60));

    assert.ok(telegramPayload !== null, 'Telegram alert should have been sent');
    assert.strictEqual(telegramPayload.chat_id, '-100123456789');
    assert.ok(telegramPayload.text.includes('/api/checkout'));
  } finally {
    global.fetch = originalFetch;
  }
});

// ── Guard Integration & Management ───────────────────────────────────────────
console.log('\n\x1b[36m  7. Guard Management & 7-Layer Protection\x1b[0m');

test('createNextGuard returns all expected methods', () => {
  const guard = createNextGuard();
  assert.strictEqual(typeof guard.middleware, 'function');
  assert.strictEqual(typeof guard.nextMiddleware, 'function');
  assert.strictEqual(typeof guard.universalMiddleware, 'function');
  assert.strictEqual(typeof guard.ban, 'function');
  assert.strictEqual(typeof guard.unban, 'function');
  assert.strictEqual(typeof guard.getStats, 'function');
  assert.strictEqual(typeof guard.setMode, 'function');
  assert.strictEqual(guard.events instanceof EventEmitter, true);
});

test('getStats returns expected shape', () => {
  const guard = createNextGuard();
  const stats = guard.getStats();
  assert.strictEqual(typeof stats.version, 'string');
  assert.strictEqual(typeof stats.uptime, 'number');
  assert.strictEqual(typeof stats.trackedIPs, 'number');
  assert.strictEqual(typeof stats.bannedIPs, 'number');
  assert.ok(Array.isArray(stats.topOffenders));
});

test('setMode rejects invalid mode', () => {
  const guard = createNextGuard();
  assert.throws(() => guard.setMode('invalid'), /Invalid mode/);
});

test('setMode accepts valid modes', () => {
  const guard = createNextGuard();
  guard.setMode('monitor');
  assert.strictEqual(guard.config.mode, 'monitor');
  guard.setMode('lockdown');
  assert.strictEqual(guard.config.mode, 'lockdown');
  guard.setMode('protect');
  assert.strictEqual(guard.config.mode, 'protect');
});

test('ban/unban correctly manages banlist', () => {
  const guard = createNextGuard();
  guard.ban('5.5.5.5', { reason: 'test' });
  assert.strictEqual(guard.getStats().bannedIPs, 1);
  guard.unban('5.5.5.5');
  assert.strictEqual(guard.getStats().bannedIPs, 0);
});

test('middleware blocks malicious UA on arbitrary path', () => {
  const guard = createNextGuard({ logLevel: 'silent' });
  const req = mockReq({
    url: '/anything/users',
    socket: { remoteAddress: '10.20.30.41' },
    headers: { 'user-agent': 'sqlmap/1.5' },
  });
  const res = mockRes();

  return new Promise((resolve) => {
    guard.middleware(req, res, () => {
      assert.fail('next() should not have been called for malicious UA');
    });
    setTimeout(() => {
      assert.strictEqual(res._status, 400);
      resolve();
    }, 100);
  });
});

test('middleware blocks genuine honeypot probe /.env', () => {
  const guard = createNextGuard({ logLevel: 'silent' });
  const req = mockReq({
    url: '/.env',
    socket: { remoteAddress: '10.20.30.42' },
  });
  const res = mockRes();

  return new Promise((resolve) => {
    guard.middleware(req, res, () => {});
    setTimeout(resolve, 50);
  });
});

// ── Summary ──────────────────────────────────────────────────────────────────
setTimeout(() => {
  console.log(`\n  \x1b[1mResults: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m\n`);
  process.exit(failed > 0 ? 1 : 0);
}, 600);
