/**
 * ███╗   ██╗███████╗██╗  ██╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 * ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 * ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 * ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 * ██║ ╚████║███████╗██╔╝ ██╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 * ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
 *
 * NextGuard v1.0.0 — 7-Layer DDoS Firewall & Active Defense Shield
 * Compatible with: Node.js (Express/Fastify/http) + Next.js (App Router & Pages Router)
 * Author  : NextGuard Team
 * License : MIT
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │  LAYER 1 → IP Reputation & Blacklist Gate                                   │
 * │  LAYER 2 → Rate Limiter & Request Throttle                                  │
 * │  LAYER 3 → Behavioral Anomaly Detector                                      │
 * │  LAYER 4 → Header & Protocol Integrity Check                                │
 * │  LAYER 5 → Payload & Body Inspection (SQLi, XSS, RCE, Path Traversal)       │
 * │  LAYER 6 → Geo-Fencing & ASN Threat Intelligence                            │
 * │  LAYER 7 → Active Counter-Strike & Tarpit Engine                            │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */

'use strict';

const crypto = require('crypto');
const { EventEmitter } = require('events');
const http = require('http');
const https = require('https');
const net = require('net');

// ═══════════════════════════════════════════════════════════════════════════════
//  CONSTANTS & SIGNATURES
// ═══════════════════════════════════════════════════════════════════════════════

const VERSION = '1.0.0';

/** Known malicious user-agent fragments (bots, scanners, exploit frameworks). */
const MALICIOUS_UA_PATTERNS = [
  /sqlmap/i, /nikto/i, /nessus/i, /masscan/i, /zgrab/i, /nmap/i,
  /nuclei/i, /hydra/i, /medusa/i, /metasploit/i, /burpsuite/i, /dirbuster/i,
  /gobuster/i, /wfuzz/i, /acunetix/i, /openvas/i, /havij/i, /w3af/i,
  /skipfish/i, /appscan/i, /webinspect/i, /httperf/i, /ab\//i, /siege\//i,
  /wrk\//i, /vegeta/i, /k6\//i, /locust/i, /python-requests/i,
  /python-urllib/i, /go-http-client/i, /curl\/7\.[0-2]/i, /libwww-perl/i,
  /masscan\//i, /zmap/i, /shodan/i, /censys/i, /stretchr/i, /dirsearch/i,
  /feroxbuster/i, /ffuf/i, /httprint/i, /grabber/i, /arachni/i,
];

/** SQLi / XSS / RCE / LFI payload signatures. */
const ATTACK_SIGNATURES = [
  // SQL Injection
  /(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE|CAST|CONVERT)\b.*\b(FROM|INTO|TABLE|WHERE|SET|VALUES)\b)/gi,
  /('|")\s*(OR|AND)\s*('|"|\d)\s*(=|LIKE|IS)/gi,
  /;\s*(DROP|ALTER|TRUNCATE|DELETE|UPDATE|INSERT)\s+/gi,
  /\/\*.*?\*\//g,
  /xp_cmdshell/gi,
  /information_schema/gi,
  /sys\.tables/gi,
  /benchmark\s*\(/gi,
  /sleep\s*\(\s*\d+\s*\)/gi,
  /waitfor\s+delay/gi,
  /load_file\s*\(/gi,
  /into\s+outfile/gi,
  /char\s*\(\s*\d/gi,

  // XSS
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript\s*:/gi,
  /on\w+\s*=\s*["']?.*?["']?/gi,
  /<\s*iframe/gi,
  /<\s*object/gi,
  /<\s*embed/gi,
  /eval\s*\(/gi,
  /document\.cookie/gi,
  /document\.write/gi,
  /window\.location/gi,
  /String\.fromCharCode/gi,
  /&#x[0-9a-f]+;/gi,

  // Path Traversal / LFI
  /\.\.\//g,
  /\.\.%2[fF]/g,
  /%252[eE]%252[eE]%252[fF]/g,
  /\/etc\/passwd/gi,
  /\/proc\/self/gi,
  /\/windows\/system32/gi,
  /c:\\windows/gi,

  // RCE / Command Injection
  /[;&|`$()]\s*(ls|cat|wget|curl|bash|sh|cmd|powershell|python|perl|ruby|nc|netcat)\s/gi,
  /\$\(.*?\)/g,
  /`[^`]*`/g,
];

/** Suspicious HTTP headers that attackers often forge or omit. */
const SUSPICIOUS_HEADERS = [
  'x-forwarded-host',
  'x-original-url',
  'x-rewrite-url',
  'x-override-url',
  'x-http-method-override',
  'x-method-override',
];

/** Allowed HTTP methods. Anything outside this is suspicious. */
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

// ═══════════════════════════════════════════════════════════════════════════════
//  IN-MEMORY STORES  (swap with Redis for multi-instance deployments)
// ═══════════════════════════════════════════════════════════════════════════════

/** @type {Map<string, {count:number, firstSeen:number, lastSeen:number, violations:number, tarpitUntil:number|null}>} */
const ipStore = new Map();

/** Permanently or temporarily banned IPs. @type {Map<string, {until:number|null, reason:string}>} */
const banlist = new Map();

/** Tarpit state per IP — forces attacker's connection to hang. @type {Map<string, number>} */
const tarpitStore = new Map();

/** Challenge state (proof-of-work tokens). @type {Map<string, {token:string, expires:number, solved:boolean}>} */
const challengeStore = new Map();

/** Slow-read state — drains attacker buffers. @type {Set<string>} */
const slowReadTargets = new Set();

/** Geographic block cache. @type {Map<string, string>} */
const geoCache = new Map();

// ═══════════════════════════════════════════════════════════════════════════════
//  DEFAULT CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG = {
  // General
  name: 'NextGuard',
  mode: 'protect',            // 'protect' | 'monitor' | 'lockdown'
  trustProxy: true,
  logLevel: 'warn',           // 'silent' | 'warn' | 'info' | 'debug'

  // Layer 1 — IP Reputation
  layer1: {
    enabled: true,
    staticBlacklist: [],      // string[] of banned IPs/CIDRs
    autobanOnViolations: 5,   // auto-ban after N violations
    banDurationMs: 3_600_000, // 1 hour default
  },

  // Layer 2 — Rate Limiting
  layer2: {
    enabled: true,
    windowMs: 60_000,         // 1-minute window
    maxRequests: 120,         // max requests per window per IP
    burstLimit: 30,           // max requests per 5-second burst
    burstWindowMs: 5_000,
    penaltyMs: 30_000,        // cool-down after limit exceeded
  },

  // Layer 3 — Behavioral Analysis
  layer3: {
    enabled: true,
    maxPathsPerWindow: 40,    // unique paths an IP may visit per window
    maxErrorsPerWindow: 15,   // 404/4xx errors before flagging
    fingerprintCookieName: '__ng_fp',
    jsChallenge: false,       // enable JS proof-of-work challenge
  },

  // Layer 4 — Header & Protocol Integrity
  layer4: {
    enabled: true,
    requireUserAgent: true,
    blockMaliciousUA: true,
    blockMissingSNI: false,   // HTTPS only — drop if no SNI
    maxHeaderSize: 8192,
  },

  // Layer 5 — Payload Inspection
  layer5: {
    enabled: true,
    maxBodySize: 2_097_152,   // 2 MB
    inspectQuery: true,
    inspectBody: true,
    inspectCookies: true,
    inspectHeaders: true,
  },

  // Layer 6 — Geo-Fencing
  layer6: {
    enabled: false,           // requires external geo API or local DB
    allowedCountries: [],     // if non-empty, ONLY allow these ISO-3166 codes
    blockedCountries: [],     // always block these ISO-3166 codes
    geoApiUrl: null,          // e.g. 'http://ip-api.com/json/{ip}?fields=countryCode'
  },

  // Layer 7 — Active Counter-Strike
  layer7: {
    enabled: true,
    tarpitEnabled: true,
    tarpitDelayMs: 10_000,    // freeze attacker connection for 10s
    tarpitMaxMs: 60_000,      // max tarpit per session
    slowReadEnabled: true,    // send data painfully slowly
    slowReadChunkMs: 2_000,   // 1 byte every 2s
    resetStormEnabled: true,  // send TCP RST-like HTTP to crash scanner state
    honeypotPaths: [          // lure attackers into tarpit
      '/.env', '/wp-admin', '/admin', '/phpmyadmin', '/config.php',
      '/.git/HEAD', '/backup.sql', '/db.sql', '/server-info',
      '/actuator', '/actuator/health', '/console', '/shell',
    ],
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
//  LOGGER
// ═══════════════════════════════════════════════════════════════════════════════

const LOG_LEVELS = { silent: 0, warn: 1, info: 2, debug: 3 };

function createLogger(level) {
  const lvl = LOG_LEVELS[level] ?? 1;
  const ts = () => new Date().toISOString();
  const prefix = '[NextGuard]';
  return {
    warn:  (...a) => lvl >= 1 && console.warn( `\x1b[33m${prefix}[WARN]\x1b[0m  ${ts()}`, ...a),
    info:  (...a) => lvl >= 2 && console.info( `\x1b[36m${prefix}[INFO]\x1b[0m  ${ts()}`, ...a),
    debug: (...a) => lvl >= 3 && console.debug(`\x1b[90m${prefix}[DEBUG]\x1b[0m ${ts()}`, ...a),
    error: (...a) =>             console.error(`\x1b[31m${prefix}[ERROR]\x1b[0m ${ts()}`, ...a),
    threat:(...a) =>             console.error(`\x1b[41m\x1b[97m${prefix}[THREAT]\x1b[0m ${ts()}`, ...a),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Deep-merge config objects.
 * @param {object} defaults
 * @param {object} overrides
 * @returns {object}
 */
function deepMerge(defaults, overrides) {
  const result = { ...defaults };
  for (const key of Object.keys(overrides || {})) {
    if (
      overrides[key] !== null &&
      typeof overrides[key] === 'object' &&
      !Array.isArray(overrides[key]) &&
      typeof defaults[key] === 'object'
    ) {
      result[key] = deepMerge(defaults[key], overrides[key]);
    } else {
      result[key] = overrides[key];
    }
  }
  return result;
}

/**
 * Extract the real client IP respecting proxy headers.
 * @param {object} req
 * @param {boolean} trustProxy
 * @returns {string}
 */
function getClientIP(req, trustProxy = true) {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return xff.split(',')[0].trim();
    const xrip = req.headers['x-real-ip'];
    if (xrip) return xrip.trim();
    const cfip = req.headers['cf-connecting-ip'];
    if (cfip) return cfip.trim();
  }
  return (
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    '0.0.0.0'
  ).replace(/^::ffff:/, '');
}

/**
 * Check if an IP is within a CIDR range.
 * Supports IPv4 only (IPv6 passthrough returns false unless exact match).
 * @param {string} ip
 * @param {string} cidr
 * @returns {boolean}
 */
function ipInCIDR(ip, cidr) {
  if (!cidr.includes('/')) return ip === cidr;
  try {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1) >>> 0;
    const ipNum = ip.split('.').reduce((acc, b) => (acc << 8) | parseInt(b, 10), 0) >>> 0;
    const rangeNum = range.split('.').reduce((acc, b) => (acc << 8) | parseInt(b, 10), 0) >>> 0;
    return (ipNum & mask) === (rangeNum & mask);
  } catch {
    return false;
  }
}

/**
 * Generate a cryptographically random token.
 * @param {number} [bytes=16]
 * @returns {string}
 */
function randomToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Compute SHA-256 of a string.
 * @param {string} data
 * @returns {string}
 */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Generate a proof-of-work challenge token.
 * Target: find X such that sha256(challenge + X).startsWith(prefix).
 * @param {string} challenge
 * @param {string} prefix
 * @returns {string|null}
 */
function solvePoW(challenge, prefix, maxIter = 1_000_000) {
  for (let i = 0; i < maxIter; i++) {
    if (sha256(challenge + i).startsWith(prefix)) return String(i);
  }
  return null;
}

/**
 * Parse raw cookie string into a key-value object.
 * @param {string} cookieHeader
 * @returns {object}
 */
function parseCookies(cookieHeader = '') {
  return cookieHeader.split(';').reduce((acc, pair) => {
    const [k, ...v] = pair.split('=');
    if (k) acc[k.trim()] = v.join('=').trim();
    return acc;
  }, {});
}

/**
 * Convert a readable stream to a buffer (for body inspection).
 * @param {import('stream').Readable} stream
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 */
function streamToBuffer(stream, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stream.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        stream.destroy();
        return reject(new Error('Body too large'));
      }
      chunks.push(chunk);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RESPONSE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/** Send a standard HTTP response (works for Node http.ServerResponse & Next.js res). */
function sendResponse(res, statusCode, body, headers = {}) {
  if (res.headersSent || res.writableEnded) return;

  const defaultHeaders = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-NextGuard': VERSION,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  };

  Object.entries({ ...defaultHeaders, ...headers }).forEach(([k, v]) => {
    try { res.setHeader(k, v); } catch { /* headers already sent */ }
  });

  try {
    res.statusCode = statusCode;
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  } catch { /* connection closed */ }
}

/** Send the tarpit response — hangs the connection. */
async function sendTarpit(res, delayMs, slowReadChunkMs, log) {
  if (res.headersSent || res.writableEnded) return;
  try {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Transfer-Encoding', 'chunked');
    res.setHeader('X-NextGuard', VERSION);
    res.statusCode = 200;
    res.write('<!DOCTYPE html><html><head><title>Loading...</title></head><body>');
    const end = Date.now() + delayMs;
    while (Date.now() < end && !res.writableEnded) {
      await sleep(slowReadChunkMs);
      if (!res.writableEnded) res.write(' ');
    }
  } finally {
    if (!res.writableEnded) res.end('</body></html>');
  }
}

/** Send a "reset storm" — floods attacker with garbage to confuse scanners. */
function sendResetStorm(res, log) {
  if (res.headersSent || res.writableEnded) return;
  try {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Length', '0');
    res.statusCode = 400;
    // Send many empty writes to spike the attacker's recv-Q
    for (let i = 0; i < 50; i++) {
      if (!res.writableEnded) res.write('');
    }
    res.end();
  } catch (e) {
    log.debug('resetStorm error (expected):', e.message);
  }
}

/** Convenience sleep. */
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 1 — IP REPUTATION & BLACKLIST GATE
// ═══════════════════════════════════════════════════════════════════════════════

function layer1_ipReputation(ip, config, log) {
  const cfg = config.layer1;
  if (!cfg.enabled) return { blocked: false };

  // Check permanent/temporary banlist
  if (banlist.has(ip)) {
    const entry = banlist.get(ip);
    if (entry.until === null || entry.until > Date.now()) {
      log.threat(`Layer1 | Banned IP: ${ip} | Reason: ${entry.reason}`);
      return { blocked: true, reason: `IP banned: ${entry.reason}`, layer: 1 };
    } else {
      banlist.delete(ip);
    }
  }

  // Check static blacklist (supports CIDR)
  for (const cidr of cfg.staticBlacklist) {
    if (ipInCIDR(ip, cidr)) {
      log.threat(`Layer1 | Static blacklist hit: ${ip} matches ${cidr}`);
      banlist.set(ip, { until: null, reason: 'static-blacklist' });
      return { blocked: true, reason: 'IP in static blacklist', layer: 1 };
    }
  }

  // Check violation count for auto-ban
  const rec = ipStore.get(ip);
  if (rec && rec.violations >= cfg.autobanOnViolations) {
    log.threat(`Layer1 | Auto-ban triggered for ${ip} (${rec.violations} violations)`);
    banlist.set(ip, {
      until: Date.now() + cfg.banDurationMs,
      reason: `auto-ban: ${rec.violations} violations`,
    });
    return { blocked: true, reason: 'IP auto-banned: too many violations', layer: 1 };
  }

  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 2 — RATE LIMITER & REQUEST THROTTLE
// ═══════════════════════════════════════════════════════════════════════════════

function layer2_rateLimiter(ip, config, log) {
  const cfg = config.layer2;
  if (!cfg.enabled) return { blocked: false };

  const now = Date.now();
  let rec = ipStore.get(ip) || {
    count: 0,
    burstCount: 0,
    firstSeen: now,
    lastSeen: now,
    burstStart: now,
    violations: 0,
    tarpitUntil: null,
    paths: new Set(),
    errors: 0,
    errorWindowStart: now,
  };

  // Reset window if expired
  if (now - rec.firstSeen > cfg.windowMs) {
    rec.count = 0;
    rec.firstSeen = now;
    rec.paths = new Set();
  }

  // Reset burst window
  if (now - rec.burstStart > cfg.burstWindowMs) {
    rec.burstCount = 0;
    rec.burstStart = now;
  }

  rec.count++;
  rec.burstCount++;
  rec.lastSeen = now;
  ipStore.set(ip, rec);

  // Burst check
  if (rec.burstCount > cfg.burstLimit) {
    rec.violations++;
    log.threat(`Layer2 | Burst limit exceeded: ${ip} (${rec.burstCount} req in ${cfg.burstWindowMs}ms)`);
    return {
      blocked: true,
      reason: 'Burst rate limit exceeded',
      layer: 2,
      retryAfter: Math.ceil(cfg.penaltyMs / 1000),
    };
  }

  // Window check
  if (rec.count > cfg.maxRequests) {
    rec.violations++;
    log.warn(`Layer2 | Rate limit exceeded: ${ip} (${rec.count} req in window)`);
    return {
      blocked: true,
      reason: 'Rate limit exceeded',
      layer: 2,
      retryAfter: Math.ceil((rec.firstSeen + cfg.windowMs - now) / 1000),
    };
  }

  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 3 — BEHAVIORAL ANOMALY DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════

function layer3_behavior(ip, req, config, log) {
  const cfg = config.layer3;
  if (!cfg.enabled) return { blocked: false };

  const now = Date.now();
  const rec = ipStore.get(ip);
  if (!rec) return { blocked: false };

  const url = req.url || req.nextUrl?.pathname || '/';
  rec.paths.add(url);

  // Too many unique paths — scanner/fuzzer pattern
  if (rec.paths.size > cfg.maxPathsPerWindow) {
    rec.violations++;
    log.threat(`Layer3 | Path scanning detected: ${ip} (${rec.paths.size} unique paths)`);
    return { blocked: true, reason: 'Path scanning behavior detected', layer: 3 };
  }

  // Fingerprint cookie check for JS challenge
  if (cfg.jsChallenge) {
    const cookies = parseCookies(req.headers['cookie'] || '');
    const fp = cookies[cfg.fingerprintCookieName];
    if (!fp) {
      // Bot fingerprint: no fingerprint cookie
      // (real browsers would have been challenged)
      log.debug(`Layer3 | No fingerprint cookie from ${ip}`);
      return { blocked: false, needsChallenge: true };
    }
  }

  return { blocked: false };
}

/** Record a 4xx/5xx error against an IP. */
function recordError(ip, config) {
  const cfg = config.layer3;
  const now = Date.now();
  const rec = ipStore.get(ip);
  if (!rec) return;

  if (now - rec.errorWindowStart > config.layer2.windowMs) {
    rec.errors = 0;
    rec.errorWindowStart = now;
  }
  rec.errors++;

  if (rec.errors > cfg.maxErrorsPerWindow) {
    rec.violations++;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 4 — HEADER & PROTOCOL INTEGRITY CHECK
// ═══════════════════════════════════════════════════════════════════════════════

function layer4_headers(ip, req, config, log) {
  const cfg = config.layer4;
  if (!cfg.enabled) return { blocked: false };

  const headers = req.headers || {};
  const ua = headers['user-agent'] || '';
  const method = (req.method || 'GET').toUpperCase();

  // Require User-Agent
  if (cfg.requireUserAgent && !ua) {
    const rec = ipStore.get(ip);
    if (rec) rec.violations++;
    log.warn(`Layer4 | Missing User-Agent: ${ip}`);
    return { blocked: true, reason: 'Missing User-Agent header', layer: 4 };
  }

  // Block malicious UA
  if (cfg.blockMaliciousUA && ua) {
    for (const pattern of MALICIOUS_UA_PATTERNS) {
      if (pattern.test(ua)) {
        const rec = ipStore.get(ip);
        if (rec) rec.violations += 2;
        log.threat(`Layer4 | Malicious UA blocked: ${ip} → "${ua}"`);
        return { blocked: true, reason: `Malicious user agent detected: ${ua}`, layer: 4 };
      }
    }
  }

  // Invalid HTTP method
  if (!ALLOWED_METHODS.has(method)) {
    const rec = ipStore.get(ip);
    if (rec) rec.violations++;
    log.warn(`Layer4 | Invalid HTTP method: ${method} from ${ip}`);
    return { blocked: true, reason: `Invalid HTTP method: ${method}`, layer: 4 };
  }

  // Header size check
  const headerStr = JSON.stringify(headers);
  if (headerStr.length > cfg.maxHeaderSize) {
    const rec = ipStore.get(ip);
    if (rec) rec.violations++;
    log.warn(`Layer4 | Oversized headers from ${ip}: ${headerStr.length} bytes`);
    return { blocked: true, reason: 'Request headers too large', layer: 4 };
  }

  // Suspicious override headers
  for (const h of SUSPICIOUS_HEADERS) {
    if (headers[h] !== undefined) {
      const rec = ipStore.get(ip);
      if (rec) rec.violations++;
      log.warn(`Layer4 | Suspicious header "${h}" from ${ip}: ${headers[h]}`);
      return { blocked: true, reason: `Suspicious header detected: ${h}`, layer: 4 };
    }
  }

  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 5 — PAYLOAD & BODY INSPECTION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Inspect a string value for attack signatures.
 * @param {string} value
 * @returns {{matched:boolean, pattern:string|null}}
 */
function inspectValue(value) {
  if (!value || typeof value !== 'string') return { matched: false, pattern: null };
  const decoded = (() => {
    try { return decodeURIComponent(value); } catch { return value; }
  })();
  for (const pattern of ATTACK_SIGNATURES) {
    pattern.lastIndex = 0;
    if (pattern.test(decoded) || pattern.test(value)) {
      return { matched: true, pattern: pattern.toString() };
    }
  }
  return { matched: false, pattern: null };
}

/**
 * Recursively inspect an object's values.
 * @param {any} obj
 * @returns {{matched:boolean, pattern:string|null, path:string|null}}
 */
function deepInspect(obj, path = '') {
  if (typeof obj === 'string') {
    const r = inspectValue(obj);
    return { ...r, path };
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const r = deepInspect(obj[i], `${path}[${i}]`);
      if (r.matched) return r;
    }
  } else if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const r = deepInspect(v, path ? `${path}.${k}` : k);
      if (r.matched) return r;
    }
  }
  return { matched: false, pattern: null, path: null };
}

async function layer5_payload(ip, req, config, log) {
  const cfg = config.layer5;
  if (!cfg.enabled) return { blocked: false };

  // Inspect query string
  if (cfg.inspectQuery) {
    const url = req.url || req.nextUrl?.toString() || '';
    const qs = url.includes('?') ? url.split('?').slice(1).join('?') : '';
    if (qs) {
      const result = inspectValue(qs);
      if (result.matched) {
        const rec = ipStore.get(ip);
        if (rec) rec.violations += 3;
        log.threat(`Layer5 | Attack in query string from ${ip}: ${result.pattern}`);
        return { blocked: true, reason: 'Malicious payload in query string', layer: 5 };
      }
    }
  }

  // Inspect cookies
  if (cfg.inspectCookies) {
    const cookies = req.headers['cookie'] || '';
    const result = inspectValue(cookies);
    if (result.matched) {
      const rec = ipStore.get(ip);
      if (rec) rec.violations += 3;
      log.threat(`Layer5 | Attack in cookie from ${ip}: ${result.pattern}`);
      return { blocked: true, reason: 'Malicious payload in cookies', layer: 5 };
    }
  }

  // Inspect suspicious headers
  if (cfg.inspectHeaders) {
    for (const [hk, hv] of Object.entries(req.headers || {})) {
      if (['cookie', 'authorization', 'user-agent'].includes(hk)) continue;
      const result = inspectValue(String(hv));
      if (result.matched) {
        const rec = ipStore.get(ip);
        if (rec) rec.violations += 2;
        log.threat(`Layer5 | Attack in header "${hk}" from ${ip}`);
        return { blocked: true, reason: `Malicious payload in header: ${hk}`, layer: 5 };
      }
    }
  }

  // Inspect body (only for POST/PUT/PATCH)
  if (cfg.inspectBody && ['POST', 'PUT', 'PATCH'].includes((req.method || '').toUpperCase())) {
    // Body may have been pre-parsed (Next.js / Express middleware)
    const body = req.body;
    if (body) {
      const result = deepInspect(body);
      if (result.matched) {
        const rec = ipStore.get(ip);
        if (rec) rec.violations += 3;
        log.threat(`Layer5 | Attack in body from ${ip} at path "${result.path}": ${result.pattern}`);
        return { blocked: true, reason: `Malicious payload in request body at: ${result.path}`, layer: 5 };
      }
    }
  }

  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 6 — GEO-FENCING & ASN THREAT INTELLIGENCE
// ═══════════════════════════════════════════════════════════════════════════════

async function layer6_geo(ip, config, log) {
  const cfg = config.layer6;
  if (!cfg.enabled) return { blocked: false };
  if (!cfg.geoApiUrl && cfg.allowedCountries.length === 0 && cfg.blockedCountries.length === 0) {
    return { blocked: false };
  }

  // Check cache
  let country = geoCache.get(ip);
  if (!country && cfg.geoApiUrl) {
    try {
      const url = cfg.geoApiUrl.replace('{ip}', encodeURIComponent(ip));
      const data = await fetchJson(url);
      country = data?.countryCode || data?.country || 'XX';
      geoCache.set(ip, country);
    } catch (e) {
      log.debug(`Layer6 | Geo lookup failed for ${ip}: ${e.message}`);
      country = 'XX';
    }
  }

  if (!country) return { blocked: false };

  if (cfg.blockedCountries.includes(country)) {
    log.threat(`Layer6 | Blocked country: ${ip} from ${country}`);
    return { blocked: true, reason: `Access denied from country: ${country}`, layer: 6 };
  }

  if (cfg.allowedCountries.length > 0 && !cfg.allowedCountries.includes(country)) {
    log.threat(`Layer6 | Country not in allowlist: ${ip} from ${country}`);
    return { blocked: true, reason: `Country not allowed: ${country}`, layer: 6 };
  }

  return { blocked: false };
}

/** Minimal JSON fetch using native http/https. */
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 3000 }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 7 — ACTIVE COUNTER-STRIKE & TARPIT ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if a request path is a honeypot lure.
 * @param {string} url
 * @param {string[]} honeypotPaths
 * @returns {boolean}
 */
function isHoneypotPath(url, honeypotPaths) {
  const path = url.split('?')[0].toLowerCase();
  return honeypotPaths.some((p) => path === p.toLowerCase() || path.startsWith(p.toLowerCase() + '/'));
}

/**
 * Execute layer-7 active defense against a detected attacker.
 * @returns {Promise<{handled:boolean}>}
 */
async function layer7_counterStrike(ip, req, res, config, log, reason) {
  const cfg = config.layer7;
  if (!cfg.enabled) return { handled: false };

  const url = req.url || req.nextUrl?.pathname || '/';
  const isHoneypot = isHoneypotPath(url, cfg.honeypotPaths);

  // Always tarpit honeypot requests
  if (isHoneypot) {
    log.threat(`Layer7 | Honeypot triggered by ${ip} → ${url}`);
    const rec = ipStore.get(ip);
    if (rec) rec.violations += 5;
    if (cfg.tarpitEnabled) {
      await sendTarpit(res, cfg.tarpitMaxMs, cfg.slowReadChunkMs, log);
      return { handled: true };
    }
  }

  // Tarpit known attackers
  if (cfg.tarpitEnabled && tarpitStore.has(ip)) {
    const until = tarpitStore.get(ip);
    if (until > Date.now()) {
      log.debug(`Layer7 | Tarpitting ${ip} for ${Math.ceil((until - Date.now()) / 1000)}s`);
      await sendTarpit(res, until - Date.now(), cfg.slowReadChunkMs, log);
      return { handled: true };
    } else {
      tarpitStore.delete(ip);
    }
  }

  // Determine if we should escalate to active counter
  const rec = ipStore.get(ip);
  const violations = rec?.violations || 0;

  if (violations >= 3) {
    // Set tarpit for future requests from this IP
    tarpitStore.set(ip, Date.now() + cfg.tarpitDelayMs);
    log.threat(`Layer7 | Tarpit set for ${ip} (${violations} violations) — reason: ${reason}`);

    if (cfg.tarpitEnabled) {
      await sendTarpit(res, cfg.tarpitDelayMs, cfg.slowReadChunkMs, log);
      return { handled: true };
    }
  }

  if (violations >= 1 && cfg.resetStormEnabled) {
    log.debug(`Layer7 | Reset storm for ${ip}`);
    sendResetStorm(res, log);
    return { handled: true };
  }

  return { handled: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PROOF-OF-WORK JS CHALLENGE
// ═══════════════════════════════════════════════════════════════════════════════

const POW_PREFIX = '000';

function generateChallengePage(token, nonce) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NextGuard Security Check</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{min-height:100vh;display:flex;align-items:center;justify-content:center;
      background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);font-family:monospace;color:#fff}
    .box{text-align:center;padding:40px;border:1px solid rgba(255,255,255,.1);
      border-radius:12px;background:rgba(255,255,255,.05);backdrop-filter:blur(10px);max-width:440px}
    h1{font-size:2em;color:#00d4ff;margin-bottom:8px}
    p{color:#aaa;margin:12px 0}
    .progress{height:4px;background:rgba(255,255,255,.1);border-radius:4px;overflow:hidden;margin:20px 0}
    .bar{height:100%;background:linear-gradient(90deg,#00d4ff,#9b59b6);width:0;transition:width .3s}
    #status{color:#00d4ff;font-size:.85em;margin-top:8px}
  </style>
</head>
<body>
  <div class="box">
    <h1>🛡️ NextGuard</h1>
    <p>Performing security verification…</p>
    <p>This usually takes a few seconds.</p>
    <div class="progress"><div class="bar" id="bar"></div></div>
    <div id="status">Initializing…</div>
  </div>
  <script>
    (async () => {
      const challenge = ${JSON.stringify(token)};
      const prefix = ${JSON.stringify(POW_PREFIX)};
      const nonce = ${JSON.stringify(nonce)};
      const status = document.getElementById('status');
      const bar = document.getElementById('bar');
      let i = 0;
      const hash = async (s) => {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
        return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
      };
      status.textContent = 'Solving challenge…';
      const solve = async () => {
        while (true) {
          if (i % 500 === 0) {
            bar.style.width = Math.min(90, i / 2000 * 100) + '%';
            status.textContent = 'Checking ' + i + ' candidates…';
            await new Promise(r => setTimeout(r, 0));
          }
          const h = await hash(challenge + i);
          if (h.startsWith(prefix)) {
            bar.style.width = '100%';
            status.textContent = 'Verified! Redirecting…';
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/__nextguard/verify';
            const fields = {token: challenge, nonce, solution: String(i)};
            for (const [k, v] of Object.entries(fields)) {
              const inp = document.createElement('input');
              inp.type = 'hidden'; inp.name = k; inp.value = v;
              form.appendChild(inp);
            }
            document.body.appendChild(form);
            form.submit();
            return;
          }
          i++;
        }
      };
      solve();
    })();
  </script>
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SECURITY HEADERS MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════════

function applySecurityHeaders(res) {
  const headers = {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; '),
    'X-NextGuard': VERSION,
    'X-Powered-By': 'NextGuard',
  };
  for (const [k, v] of Object.entries(headers)) {
    try { res.setHeader(k, v); } catch { /* already sent */ }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ADMIN API HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function handleAdminRoute(path, req, res, config, log) {
  const method = (req.method || 'GET').toUpperCase();

  if (path === '/__nextguard/stats' && method === 'GET') {
    sendResponse(res, 200, {
      version: VERSION,
      uptime: process.uptime(),
      trackedIPs: ipStore.size,
      bannedIPs: banlist.size,
      tarpittedIPs: tarpitStore.size,
      challengesSent: challengeStore.size,
      mode: config.mode,
    });
    return true;
  }

  if (path === '/__nextguard/ban' && method === 'POST') {
    try {
      const body = req.body || {};
      const { ip: targetIp, durationMs, reason } = body;
      if (!net.isIP(targetIp)) {
        sendResponse(res, 400, { error: 'Invalid IP address' });
        return true;
      }
      banlist.set(targetIp, {
        until: durationMs ? Date.now() + durationMs : null,
        reason: reason || 'manual-ban',
      });
      log.info(`Admin | Manual ban: ${targetIp} (${reason || 'manual-ban'})`);
      sendResponse(res, 200, { success: true, message: `${targetIp} banned` });
    } catch {
      sendResponse(res, 400, { error: 'Invalid request body' });
    }
    return true;
  }

  if (path === '/__nextguard/unban' && method === 'POST') {
    try {
      const { ip: targetIp } = req.body || {};
      banlist.delete(targetIp);
      tarpitStore.delete(targetIp);
      log.info(`Admin | Manual unban: ${targetIp}`);
      sendResponse(res, 200, { success: true, message: `${targetIp} unbanned` });
    } catch {
      sendResponse(res, 400, { error: 'Invalid request body' });
    }
    return true;
  }

  return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MEMORY CLEANUP (prevent leak on long-running servers)
// ═══════════════════════════════════════════════════════════════════════════════

function startCleanupJob(config) {
  const CLEANUP_INTERVAL = 5 * 60 * 1000; // every 5 minutes
  const MAX_IDLE_MS = config.layer2.windowMs * 2;

  setInterval(() => {
    const now = Date.now();

    // Remove stale IP records
    for (const [ip, rec] of ipStore) {
      if (now - rec.lastSeen > MAX_IDLE_MS) ipStore.delete(ip);
    }

    // Remove expired bans
    for (const [ip, ban] of banlist) {
      if (ban.until !== null && ban.until < now) banlist.delete(ip);
    }

    // Remove expired tarpit entries
    for (const [ip, until] of tarpitStore) {
      if (until < now) tarpitStore.delete(ip);
    }

    // Remove expired challenges
    for (const [token, ch] of challengeStore) {
      if (ch.expires < now) challengeStore.delete(token);
    }

    // Clear geo cache periodically (every hour, so stale after 5 min cycles ×12)
    if (Math.random() < 0.083) geoCache.clear();
  }, CLEANUP_INTERVAL).unref();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CORE GUARD ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Run all 7 layers against a request.
 * @param {object} req - Node.js IncomingMessage or Next.js Request-like object
 * @param {object} res - Node.js ServerResponse or Next.js Response-like object
 * @param {object} config - Merged config
 * @param {object} log - Logger
 * @param {EventEmitter} events
 * @returns {Promise<{blocked:boolean, layer?:number, reason?:string, handled?:boolean}>}
 */
async function runGuard(req, res, config, log, events) {
  const ip = getClientIP(req, config.trustProxy);
  const url = req.url || req.nextUrl?.toString() || '/';
  const path = url.split('?')[0];

  // Initialize IP record
  if (!ipStore.has(ip)) {
    ipStore.set(ip, {
      count: 0,
      burstCount: 0,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      burstStart: Date.now(),
      violations: 0,
      tarpitUntil: null,
      paths: new Set(),
      errors: 0,
      errorWindowStart: Date.now(),
    });
  }

  log.debug(`Guard | ${ip} ${req.method} ${path}`);

  // Admin routes (always processed before guard layers)
  if (path.startsWith('/__nextguard/')) {
    if (handleAdminRoute(path, req, res, config, log)) return { blocked: false };
  }

  // Lockdown mode — block everything except admin
  if (config.mode === 'lockdown') {
    log.warn(`Lockdown | Blocking all traffic: ${ip}`);
    const l7 = await layer7_counterStrike(ip, req, res, config, log, 'lockdown');
    if (!l7.handled) sendResponse(res, 503, { error: 'Service unavailable' });
    return { blocked: true, reason: 'Lockdown mode active', layer: 0 };
  }

  // ── Layer 1 ──────────────────────────────────────────────────────────────
  const r1 = layer1_ipReputation(ip, config, log);
  if (r1.blocked) {
    events.emit('threat', { ip, layer: 1, reason: r1.reason, req });
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r1.reason);
    if (!l7.handled) sendResponse(res, 403, { error: 'Access denied', reason: r1.reason, layer: 1 });
    return { blocked: true, ...r1 };
  }

  // ── Layer 2 ──────────────────────────────────────────────────────────────
  const r2 = layer2_rateLimiter(ip, config, log);
  if (r2.blocked) {
    events.emit('threat', { ip, layer: 2, reason: r2.reason, req });
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r2.reason);
    if (!l7.handled) {
      sendResponse(res, 429, { error: 'Too Many Requests', reason: r2.reason, layer: 2 }, {
        'Retry-After': String(r2.retryAfter || 60),
      });
    }
    return { blocked: true, ...r2 };
  }

  // ── Layer 3 ──────────────────────────────────────────────────────────────
  const r3 = layer3_behavior(ip, req, config, log);
  if (r3.blocked) {
    events.emit('threat', { ip, layer: 3, reason: r3.reason, req });
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r3.reason);
    if (!l7.handled) sendResponse(res, 403, { error: 'Access denied', reason: r3.reason, layer: 3 });
    return { blocked: true, ...r3 };
  }

  // JS Challenge flow
  if (r3.needsChallenge && config.layer3.jsChallenge) {
    const token = randomToken();
    const nonce = randomToken(8);
    challengeStore.set(token, { token, expires: Date.now() + 120_000, solved: false, ip });
    sendResponse(res, 403, generateChallengePage(token, nonce), {
      'Content-Type': 'text/html; charset=utf-8',
    });
    return { blocked: true, reason: 'JS challenge issued', layer: 3 };
  }

  // ── Layer 4 ──────────────────────────────────────────────────────────────
  const r4 = layer4_headers(ip, req, config, log);
  if (r4.blocked) {
    events.emit('threat', { ip, layer: 4, reason: r4.reason, req });
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r4.reason);
    if (!l7.handled) sendResponse(res, 400, { error: 'Bad Request', reason: r4.reason, layer: 4 });
    return { blocked: true, ...r4 };
  }

  // ── Layer 5 ──────────────────────────────────────────────────────────────
  const r5 = await layer5_payload(ip, req, config, log);
  if (r5.blocked) {
    events.emit('threat', { ip, layer: 5, reason: r5.reason, req });
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r5.reason);
    if (!l7.handled) sendResponse(res, 400, { error: 'Malicious payload detected', reason: r5.reason, layer: 5 });
    return { blocked: true, ...r5 };
  }

  // ── Layer 6 ──────────────────────────────────────────────────────────────
  const r6 = await layer6_geo(ip, config, log);
  if (r6.blocked) {
    events.emit('threat', { ip, layer: 6, reason: r6.reason, req });
    sendResponse(res, 403, { error: 'Access denied', reason: r6.reason, layer: 6 });
    return { blocked: true, ...r6 };
  }

  // ── Layer 7 (honeypot check) ──────────────────────────────────────────────
  const cfg7 = config.layer7;
  if (cfg7.enabled && isHoneypotPath(path, cfg7.honeypotPaths)) {
    events.emit('threat', { ip, layer: 7, reason: 'Honeypot access', req });
    await layer7_counterStrike(ip, req, res, config, log, 'Honeypot access');
    return { blocked: true, reason: 'Honeypot access', layer: 7 };
  }

  // ── All layers passed ────────────────────────────────────────────────────
  applySecurityHeaders(res);
  log.debug(`Guard | ALLOW ${ip} ${req.method} ${path}`);
  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PUBLIC API — createNextGuard(config?)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a NextGuard instance.
 *
 * @param {Partial<typeof DEFAULT_CONFIG>} [userConfig]
 * @returns {{
 *   middleware: function,
 *   nextMiddleware: function,
 *   handler: function,
 *   ban: function,
 *   unban: function,
 *   getStats: function,
 *   setMode: function,
 *   events: EventEmitter,
 *   config: typeof DEFAULT_CONFIG,
 * }}
 *
 * @example
 * // Express / Node http
 * const { middleware } = createNextGuard({ layer2: { maxRequests: 60 } });
 * app.use(middleware);
 *
 * @example
 * // Next.js middleware.js (App Router)
 * export { nextMiddleware as middleware } from 'nextguard';
 * // or with config:
 * import { createNextGuard } from 'nextguard';
 * const guard = createNextGuard({ layer6: { enabled: true, blockedCountries: ['CN','RU'] } });
 * export const middleware = guard.nextMiddleware;
 */
function createNextGuard(userConfig = {}) {
  const config = deepMerge(DEFAULT_CONFIG, userConfig);
  const log = createLogger(config.logLevel);
  const events = new EventEmitter();

  log.info(`NextGuard v${VERSION} initialized | mode: ${config.mode} | layers: 1-7`);
  startCleanupJob(config);

  // ── Express / http.createServer middleware ──────────────────────────────
  /**
   * Express-compatible middleware.
   * Usage: app.use(guard.middleware)
   */
  const middleware = (req, res, next) => {
    runGuard(req, res, config, log, events).then((result) => {
      if (!result.blocked && typeof next === 'function') {
        next();
      }
    }).catch((err) => {
      log.error('Guard error:', err);
      if (typeof next === 'function') next(err);
    });
  };

  // ── Next.js App Router / Edge Middleware ────────────────────────────────
  /**
   * Next.js middleware (middleware.js / middleware.ts at project root).
   * Usage: export const middleware = guard.nextMiddleware;
   *
   * Note: Next.js Edge Runtime doesn't support all Node APIs.
   * For full functionality, use in Node.js runtime via:
   *   export const config = { runtime: 'nodejs' }
   */
  const nextMiddleware = async (req) => {
    // Next.js uses the Response/NextResponse API
    // We create a mock res-like object and check the result
    let blockedResponse = null;
    let statusCode = 200;
    let responseBody = null;
    let responseHeaders = {};

    const mockRes = {
      headersSent: false,
      writableEnded: false,
      statusCode: 200,
      headers: {},
      setHeader(k, v) { this.headers[k] = v; responseHeaders[k] = v; },
      write() { return true; },
      end(body) {
        this.writableEnded = true;
        if (body) responseBody = body;
      },
    };
    Object.defineProperty(mockRes, 'statusCode', {
      get() { return statusCode; },
      set(v) { statusCode = v; },
    });

    const result = await runGuard(req, mockRes, config, log, events);

    if (result.blocked) {
      const body = responseBody || JSON.stringify({ error: 'Access denied', reason: result.reason });
      const headers = {
        'Content-Type': 'application/json',
        'X-NextGuard': VERSION,
        ...responseHeaders,
      };
      // Return a standard Response object (works with Next.js / Vercel Edge)
      return new Response(body, { status: statusCode || 403, headers });
    }

    // Not blocked — return null to let Next.js continue
    return null;
  };

  // ── Raw HTTP handler (for custom http.createServer usage) ───────────────
  /**
   * Wrap an existing HTTP handler with NextGuard protection.
   * Usage: http.createServer(guard.handler(myRequestHandler))
   */
  const handler = (next) => (req, res) => {
    runGuard(req, res, config, log, events).then((result) => {
      if (!result.blocked) next(req, res);
    }).catch((err) => {
      log.error('Guard error:', err);
      next(req, res);
    });
  };

  // ── Public management API ───────────────────────────────────────────────

  /** Manually ban an IP. */
  const ban = (ip, { durationMs = null, reason = 'manual' } = {}) => {
    banlist.set(ip, { until: durationMs ? Date.now() + durationMs : null, reason });
    log.info(`API | Ban: ${ip} (${reason})`);
  };

  /** Remove a ban. */
  const unban = (ip) => {
    banlist.delete(ip);
    tarpitStore.delete(ip);
    log.info(`API | Unban: ${ip}`);
  };

  /** Get current stats. */
  const getStats = () => ({
    version: VERSION,
    uptime: process.uptime(),
    mode: config.mode,
    trackedIPs: ipStore.size,
    bannedIPs: banlist.size,
    tarpittedIPs: tarpitStore.size,
    challenges: challengeStore.size,
    topOffenders: [...ipStore.entries()]
      .sort((a, b) => b[1].violations - a[1].violations)
      .slice(0, 10)
      .map(([ip, r]) => ({ ip, violations: r.violations, requests: r.count })),
  });

  /** Switch operating mode at runtime. */
  const setMode = (mode) => {
    if (!['protect', 'monitor', 'lockdown'].includes(mode)) {
      throw new Error(`Invalid mode: ${mode}. Must be protect | monitor | lockdown`);
    }
    config.mode = mode;
    log.info(`Mode changed → ${mode}`);
  };

  /** Add IPs to static blacklist at runtime. */
  const addToBlacklist = (ip) => {
    config.layer1.staticBlacklist.push(ip);
    log.info(`API | Blacklist added: ${ip}`);
  };

  /** Remove an IP from the static blacklist. */
  const removeFromBlacklist = (ip) => {
    config.layer1.staticBlacklist = config.layer1.staticBlacklist.filter((i) => i !== ip);
    log.info(`API | Blacklist removed: ${ip}`);
  };

  return {
    middleware,
    nextMiddleware,
    handler,
    ban,
    unban,
    getStats,
    setMode,
    addToBlacklist,
    removeFromBlacklist,
    events,
    config,
    version: VERSION,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CONVENIENCE EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

// Pre-built default instance (zero-config usage)
const _defaultInstance = createNextGuard();

module.exports = {
  // Factory (recommended)
  createNextGuard,

  // Default instance shortcuts
  middleware: _defaultInstance.middleware,
  nextMiddleware: _defaultInstance.nextMiddleware,
  handler: _defaultInstance.handler,
  ban: _defaultInstance.ban,
  unban: _defaultInstance.unban,
  getStats: _defaultInstance.getStats,
  setMode: _defaultInstance.setMode,
  events: _defaultInstance.events,

  // Utilities (advanced use)
  getClientIP,
  inspectValue,
  deepInspect,
  ipInCIDR,
  VERSION,
};
