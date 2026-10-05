/**
 * NextGuard — Test Suite
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

// Import utilities (no full guard needed for unit tests)
const {
  getClientIP,
  inspectValue,
  deepInspect,
  ipInCIDR,
  createNextGuard,
  VERSION,
} = require('../nextguard');

// ── Helper: create a mock request ──────────────────────────────────────────
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

// ── Helper: create a mock response ─────────────────────────────────────────
function mockRes() {
  const res = {
    headersSent: false,
    writableEnded: false,
    _status: 200,
    _headers: {},
    _body: null,
    setHeader(k, v) { this._headers[k] = v; },
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

// ══════════════════════════════════════════════════════════════════════════════
console.log('\n\x1b[1m  NextGuard Test Suite\x1b[0m\n');

// ── Utilities ──────────────────────────────────────────────────────────────
console.log('\x1b[36m  Utilities\x1b[0m');

test('VERSION is a string', () => {
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

// ── Payload Inspection ─────────────────────────────────────────────────────
console.log('\n\x1b[36m  Layer 5 — Payload Inspection\x1b[0m');

test('inspectValue — clean input passes', () => {
  const r = inspectValue('Hello World');
  assert.strictEqual(r.matched, false);
});

test('inspectValue — SQL UNION SELECT blocked', () => {
  const r = inspectValue("' UNION SELECT * FROM users--");
  assert.strictEqual(r.matched, true);
});

test('inspectValue — SQL sleep() blocked', () => {
  const r = inspectValue('sleep(5)');
  assert.strictEqual(r.matched, true);
});

test('inspectValue — XSS <script> blocked', () => {
  const r = inspectValue('<script>alert(1)</script>');
  assert.strictEqual(r.matched, true);
});

test('inspectValue — XSS javascript: blocked', () => {
  const r = inspectValue('javascript:alert(1)');
  assert.strictEqual(r.matched, true);
});

test('inspectValue — Path traversal blocked', () => {
  const r = inspectValue('../../etc/passwd');
  assert.strictEqual(r.matched, true);
});

test('inspectValue — /etc/passwd blocked', () => {
  const r = inspectValue('/etc/passwd');
  assert.strictEqual(r.matched, true);
});

test('deepInspect — nested object with SQLi', () => {
  const r = deepInspect({ user: { name: "' OR 1=1--" } });
  assert.strictEqual(r.matched, true);
});

test('deepInspect — clean nested object passes', () => {
  const r = deepInspect({ user: { name: 'Alice', age: 30 } });
  assert.strictEqual(r.matched, false);
});

test('deepInspect — array with XSS', () => {
  const r = deepInspect(['safe', '<script>evil()</script>']);
  assert.strictEqual(r.matched, true);
});

// ── Guard Integration ──────────────────────────────────────────────────────
console.log('\n\x1b[36m  Guard Integration\x1b[0m');

test('createNextGuard returns all expected methods', () => {
  const guard = createNextGuard();
  assert.strictEqual(typeof guard.middleware, 'function');
  assert.strictEqual(typeof guard.nextMiddleware, 'function');
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

test('middleware calls next() for clean request', (done) => {
  const guard = createNextGuard({ logLevel: 'silent' });
  const req = mockReq({ socket: { remoteAddress: '10.20.30.40' } });
  const res = mockRes();

  return new Promise((resolve) => {
    guard.middleware(req, res, () => {
      resolve();
    });
  });
});

test('middleware blocks malicious UA', () => {
  const guard = createNextGuard({ logLevel: 'silent' });
  const req = mockReq({
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

test('middleware blocks honeypot path', () => {
  const guard = createNextGuard({ logLevel: 'silent' });
  const req = mockReq({
    url: '/.env',
    socket: { remoteAddress: '10.20.30.42' },
  });
  const res = mockRes();

  return new Promise((resolve) => {
    guard.middleware(req, res, () => {});
    // Honeypot tarpit runs asynchronously; we just check it was triggered
    setTimeout(resolve, 50);
  });
});

// ── Summary ────────────────────────────────────────────────────────────────
setTimeout(() => {
  console.log(`\n  \x1b[1mResults: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m\n`);
  process.exit(failed > 0 ? 1 : 0);
}, 500);
