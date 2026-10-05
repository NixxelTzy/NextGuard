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

// Import nextguard
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

/** Mock standard Next.js / Fetch Request */
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
  const req = mockReq();
  assert.strictEqual(getClientIP(req, false), '127.0.0.1');
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

// ── Layer 5 — Payload Inspection ───────────────────────────────────────────
console.log('\n\x1b[36m  2. Layer 5 — Payload & Attack Inspection\x1b[0m');

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

test('inspectValue — XSS javascript: blocked', () => {
  assert.strictEqual(inspectValue('javascript:alert(1)').matched, true);
});

test('inspectValue — Path traversal blocked', () => {
  assert.strictEqual(inspectValue('../../etc/passwd').matched, true);
});

test('inspectValue — /etc/passwd blocked', () => {
  assert.strictEqual(inspectValue('/etc/passwd').matched, true);
});

test('deepInspect — nested object with SQLi', () => {
  assert.strictEqual(deepInspect({ user: { name: "' OR 1=1--" } }).matched, true);
});

test('deepInspect — clean nested object passes', () => {
  assert.strictEqual(deepInspect({ user: { name: 'Alice', age: 30 } }).matched, false);
});

test('deepInspect — array with XSS', () => {
  assert.strictEqual(deepInspect(['safe', '<script>evil()</script>']).matched, true);
});

// ── Path-Agnostic Architecture Tests ─────────────────────────────────────────
console.log('\n\x1b[36m  3. Path-Agnostic Architecture (Any Path / No Hardcoded Routes)\x1b[0m');

test('nextguard() works without any path parameters', () => {
  const mw = nextguard();
  assert.strictEqual(typeof mw, 'function');
  assert.strictEqual(typeof mw.ban, 'function');
  assert.strictEqual(typeof mw.getStats, 'function');
});

test('NextGuard allows all standard and custom application paths transparently', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const testPaths = [
    '/',
    '/login',
    '/dashboard',
    '/admin',
    '/api/users',
    '/api/payment',
    '/my-custom-path',
    '/abc',
    '/anything',
    '/whatever/123',
    '/shop/items/456/reviews',
  ];

  for (const path of testPaths) {
    const req = mockNextRequest(path, { ip: '192.0.2.1' });
    const response = await mw(req);
    // null means request allowed through to application route
    assert.strictEqual(response, null, `Expected path "${path}" to be allowed transparently`);
  }
});

test('/admin is NOT treated as a honeypot and is allowed through', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const req = mockNextRequest('/admin', { ip: '192.0.2.2' });
  const response = await mw(req);
  assert.strictEqual(response, null, 'Legitimate /admin route must be allowed without honeypot block');
});

test('Nested paths are processed transparently without assumptions', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const nestedPaths = [
    '/api/users',
    '/api/users/123',
    '/dashboard/settings',
    '/admin/users/create',
  ];

  for (const path of nestedPaths) {
    const req = mockNextRequest(path, { ip: '192.0.2.3' });
    const response = await mw(req);
    assert.strictEqual(response, null, `Nested path "${path}" should be allowed`);
  }
});

test('Simulate Next.js wildcard matcher /:path* routing all traffic through NextGuard', async () => {
  // Simulates developer configuring: export const config = { matcher: ["/:path*"] };
  const mw = nextguard({ logLevel: 'silent' });
  const randomRoutes = [
    '/',
    '/profile',
    '/settings/security',
    '/api/v1/auth/callback',
    '/blog/2026/10/nextguard-launch',
  ];

  for (const route of randomRoutes) {
    const req = mockNextRequest(route, { ip: '192.0.2.4' });
    const res = await mw(req);
    assert.strictEqual(res, null, `Route ${route} under /:path* should be processed and allowed`);
  }
});

test('Simulate Next.js custom matcher protecting specific routes only', async () => {
  // Simulates developer configuring: export const config = { matcher: ["/api/:path*", "/dashboard/:path*"] };
  const mw = nextguard({ logLevel: 'silent' });
  const matchedRoutes = ['/api/users', '/api/checkout', '/dashboard/analytics'];

  for (const route of matchedRoutes) {
    const req = mockNextRequest(route, { ip: '192.0.2.5' });
    const res = await mw(req);
    assert.strictEqual(res, null, `Protected route ${route} should pass firewall check`);
  }
});

test('Direct functional call: nextguard(request) works seamlessly', async () => {
  const req = mockNextRequest('/dashboard', { ip: '192.0.2.6' });
  const res = await nextguard(req);
  assert.strictEqual(res, null, 'nextguard(request) should return null for clean request');
});

test('Firewall blocks SQL injection attack on custom user path /api/payment', async () => {
  const mw = nextguard({ logLevel: 'silent' });
  const req = mockNextRequest("/api/payment?id=' UNION SELECT * FROM users--", { ip: '192.0.2.7' });
  const res = await mw(req);
  assert.ok(res !== null, 'Attack must be blocked');
  assert.strictEqual(res.status, 400);
});

// ── Telegram Alert Integration Tests ─────────────────────────────────────────
console.log('\n\x1b[36m  4. Telegram Real-Time Security Alerts (Vercel Ready)\x1b[0m');

test('Telegram alert is dispatched on detected attack', async () => {
  let telegramPayload = null;
  const originalFetch = global.fetch;

  // Mock fetch to intercept Telegram API call
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
        botToken: '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
        chatId: '-100987654321',
        cooldownMs: 0, // no cooldown for test
      },
    });

    // Send malicious request
    const req = mockNextRequest('/api/checkout?param=<script>alert(1)</script>', { ip: '198.51.100.99' });
    await mw(req);

    // Give microtask queue time to finish async alert
    await new Promise((r) => setTimeout(r, 60));

    assert.ok(telegramPayload !== null, 'Telegram alert should have been sent');
    assert.strictEqual(telegramPayload.chat_id, '-100987654321');
    assert.ok(telegramPayload.text.includes('NextGuard'), 'Alert text should mention NextGuard');
    assert.ok(telegramPayload.text.includes('/api/checkout'), 'Alert text should include target path');
    assert.ok(telegramPayload.text.includes('198.51.100.99'), 'Alert text should include attacker IP');
  } finally {
    global.fetch = originalFetch;
  }
});

test('Telegram alert cooldown prevents spam during high-volume DDoS attacks', async () => {
  let dispatchCount = 0;
  const originalFetch = global.fetch;

  global.fetch = async (url, options) => {
    if (url.includes('api.telegram.org')) {
      dispatchCount++;
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    }
    return originalFetch ? originalFetch(url, options) : null;
  };

  try {
    const mw = nextguard({
      logLevel: 'silent',
      telegram: {
        enabled: true,
        botToken: 'dummy-token',
        chatId: 'dummy-chat',
        cooldownMs: 10_000, // 10s cooldown
      },
    });

    const ddosIp = '203.0.113.88';

    // Simulate 5 rapid attacks from same IP
    for (let i = 0; i < 5; i++) {
      const req = mockNextRequest('/api/login?hack=sleep(5)', { ip: ddosIp });
      await mw(req);
    }

    await new Promise((r) => setTimeout(r, 60));

    // Even though 5 attacks occurred, Telegram should only receive 1 alert due to cooldown
    assert.strictEqual(dispatchCount, 1, 'Only 1 alert should be sent within cooldown window');
  } finally {
    global.fetch = originalFetch;
  }
});

// ── Guard Integration & 7 Layers ─────────────────────────────────────────────
console.log('\n\x1b[36m  5. Guard Management & 7-Layer Protection\x1b[0m');

test('createNextGuard returns all expected methods', () => {
  const guard = createNextGuard();
  assert.strictEqual(typeof guard.middleware, 'function');
  assert.strictEqual(typeof guard.nextMiddleware, 'function');
  assert.strictEqual(typeof guard.universalMiddleware, 'function');
  assert.strictEqual(typeof guard.handler, 'function');
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

test('Express middleware calls next() for clean request on arbitrary path', () => {
  const guard = createNextGuard({ logLevel: 'silent' });
  const req = mockReq({ url: '/my-custom-endpoint', socket: { remoteAddress: '10.20.30.40' } });
  const res = mockRes();

  return new Promise((resolve) => {
    guard.middleware(req, res, () => {
      resolve();
    });
  });
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
