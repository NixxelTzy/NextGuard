/**
 * ███╗   ██╗███████╗██╗  ██╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 * ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 * ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 * ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 * ██║ ╚████║███████╗██╔╝ ██╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 * ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
 *
 * NextGuard v1.1.1 — 7-Layer DDoS Firewall & Active Defense Shield
 * Universal Security Engine for Node.js (Express/Fastify/http) & Next.js (App/Pages/Edge/Vercel)
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │  LAYER 1 → IP Reputation & Blacklist Gate                                   │
 * │  LAYER 2 → Rate Limiter & Burst DDoS Throttle                               │
 * │  LAYER 3 → Behavioral Anomaly Detector                                      │
 * │  LAYER 4 → Header & Protocol Integrity Check                                │
 * │  LAYER 5 → Payload & Body Inspection (SQLi, XSS, RCE, Path Traversal)       │
 * │  LAYER 6 → Geo-Fencing & ASN Threat Intelligence                            │
 * │  LAYER 7 → Active Counter-Strike & Tarpit Engine                            │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * ZERO-FALSE-POSITIVE ARCHITECTURE:
 * - Automatically bypasses static assets (/_next/static/*, images, fonts, css)
 * - Safe auth inspection: Passwords, CSRF tokens, and JWT cookies are never falsely flagged
 * - Safe Vercel/Edge execution: Non-blocking instant 429/403 instead of serverless execution freeze
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

const VERSION = '1.1.1';

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

/** Strict SQLi / XSS / RCE / LFI payload signatures (tuned against false positives). */
const ATTACK_SIGNATURES = [
  // SQL Injection
  /(\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT|SELECT\s+.*?\s+FROM|INSERT\s+INTO\s+.*?\s+VALUES|DELETE\s+FROM|DROP\s+TABLE|DROP\s+DATABASE|ALTER\s+TABLE)\b)/gi,
  /('|")\s*(OR|AND)\s*('|"|\d)\s*(=|LIKE|IS)/gi,
  /;\s*(DROP|ALTER|TRUNCATE|DELETE\s+FROM)\s+/gi,
  /\/\*.*?\*\//g,
  /xp_cmdshell/gi,
  /information_schema\./gi,
  /sys\.tables/gi,
  /benchmark\s*\(\s*\d+\s*,/gi,
  /sleep\s*\(\s*\d+\s*\)/gi,
  /waitfor\s+delay\s+['"]/gi,
  /load_file\s*\(/gi,
  /into\s+outfile\s+['"]/gi,

  // XSS
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript\s*:\s*[a-z0-9_]/gi,
  /on(error|load|click|mouseover|focus|submit)\s*=\s*["']?.*?["']?/gi,
  /<\s*iframe[\s\S]*?>/gi,
  /<\s*object[\s\S]*?>/gi,
  /<\s*embed[\s\S]*?>/gi,
  /document\.cookie/gi,
  /document\.write\s*\(/gi,
  /window\.location\s*=/gi,
  /String\.fromCharCode\s*\(/gi,
  /&#x[0-9a-f]+;/gi,

  // Path Traversal / LFI
  /\.\.\//g,
  /\.\.%2[fF]/g,
  /%252[eE]%252[eE]%252[fF]/g,
  /\/etc\/passwd/gi,
  /\/proc\/self\/environ/gi,
  /\/windows\/system32\//gi,
  /c:\\windows\\system32/gi,

  // RCE / Command Injection (requires command execution context)
  /[;&|`$]\s*(cat\s+\/etc\/|wget\s+http|curl\s+http|bash\s+-i|powershell\s+-enc|nc\s+-e|netcat\s+-e)/gi,
  /\$\(\s*(cat|ls|id|whoami|uname|curl|wget)\b/gi,
  /`\s*(cat|ls|id|whoami|uname|curl|wget)\b/gi,
];

/** Safe form and body fields that must never be flagged as SQLi/RCE false positives. */
const SAFE_BODY_FIELDS = new Set([
  'password',
  'confirmpassword',
  'currentpassword',
  'newpassword',
  'oldpassword',
  'token',
  'accesstoken',
  'refreshtoken',
  'csrftoken',
  '_csrf',
  'signature',
  'hash',
  'secret',
  'credential',
  'code',
  'authcode',
  'session',
]);

/** Standard browser/framework headers that must be exempt from generic payload inspection. */
const SAFE_HEADERS = new Set([
  'cookie',
  'authorization',
  'user-agent',
  'accept',
  'accept-encoding',
  'accept-language',
  'sec-ch-ua',
  'sec-ch-ua-platform',
  'sec-ch-ua-mobile',
  'referer',
  'origin',
  'host',
  'connection',
  'cache-control',
  'pragma',
  'content-type',
  'content-length',
  'next-action',
  'next-router-prefetch',
  'next-router-state-tree',
  'next-url',
  'rsc',
  'purpose',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'x-real-ip',
  'cf-connecting-ip',
  'cf-ray',
  'cf-visitor',
  'traceparent',
]);

/** Known auth/session cookie prefixes to exclude from naive regex inspection. */
const SAFE_COOKIE_PREFIXES = [
  'next-auth',
  '__secure-next-auth',
  '__host-next-auth',
  'supabase',
  'sb-',
  'clerk',
  '_ga',
  '_gid',
  '_gat',
  'ph_',
  'mp_',
  'ajs_',
  'intercom',
];

/** Suspicious HTTP override headers that attackers use to spoof endpoints. */
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
//  IN-MEMORY STORES
// ═══════════════════════════════════════════════════════════════════════════════

/** @type {Map<string, {count:number, burstCount:number, firstSeen:number, lastSeen:number, burstStart:number, violations:number, tarpitUntil:number|null, paths:Set<string>, errors:number, errorWindowStart:number}>} */
const ipStore = new Map();

/** Permanently or temporarily banned IPs. @type {Map<string, {until:number|null, reason:string}>} */
const banlist = new Map();

/** Tarpit state per IP — forces attacker's connection to hang on raw servers. @type {Map<string, number>} */
const tarpitStore = new Map();

/** Challenge state (proof-of-work tokens). @type {Map<string, {token:string, expires:number, solved:boolean, ip:string}>} */
const challengeStore = new Map();

/** Geographic block cache. @type {Map<string, string>} */
const geoCache = new Map();

/** Telegram alert cooldown tracker per IP+layer to prevent DDoS alert floods. @type {Map<string, number>} */
const telegramCooldown = new Map();

// ═══════════════════════════════════════════════════════════════════════════════
//  DEFAULT CONFIGURATION (Tuned for Real Web Apps & Next.js)
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG = {
  // General
  name: 'NextGuard',
  mode: 'protect',            // 'protect' | 'monitor' | 'lockdown'
  trustProxy: true,
  logLevel: 'warn',           // 'silent' | 'warn' | 'info' | 'debug'

  // Telegram Notifications (Optimized for Vercel)
  telegram: {
    enabled: false,           // true to enable, or auto-enabled if env vars are present
    botToken: null,           // e.g. process.env.TELEGRAM_BOT_TOKEN
    chatId: null,             // e.g. process.env.TELEGRAM_CHAT_ID
    cooldownMs: 30_000,       // 30s debounce between alerts per IP+layer (prevents DDoS flood)
    minLayer: 1,              // minimum layer to trigger alert (1-7)
  },

  // Optional Admin API (disabled by default so NextGuard claims ZERO routes)
  admin: {
    enabled: false,           // false by default; NextGuard does not claim any internal routes
    routePrefix: '/__nextguard',
  },

  // Layer 1 — IP Reputation
  layer1: {
    enabled: true,
    staticBlacklist: [],      // string[] of banned IPs/CIDRs
    autobanOnViolations: 5,   // auto-ban after N violations
    banDurationMs: 3_600_000, // 1 hour default
  },

  // Layer 2 — Rate Limiting & DDoS Prevention
  layer2: {
    enabled: true,
    windowMs: 60_000,         // 1-minute window
    maxRequests: 240,         // max requests per window per IP (allows normal page loads)
    burstLimit: 60,           // max requests per 5-second burst (allows page + API calls)
    burstWindowMs: 5_000,
    penaltyMs: 30_000,        // cool-down after limit exceeded
  },

  // Layer 3 — Behavioral Analysis
  layer3: {
    enabled: true,
    maxPathsPerWindow: 80,    // unique paths an IP may visit per window (excluding static assets)
    maxErrorsPerWindow: 20,   // 404/4xx errors before flagging
    fingerprintCookieName: '__ng_fp',
    jsChallenge: false,       // enable JS proof-of-work challenge
  },

  // Layer 4 — Header & Protocol Integrity
  layer4: {
    enabled: true,
    requireUserAgent: true,
    blockMaliciousUA: true,
    blockMissingSNI: false,
    maxHeaderSize: 16384,     // 16 KB (accommodates large auth cookies)
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
    tarpitDelayMs: 10_000,    // freeze attacker connection on raw Node HTTP servers
    tarpitMaxMs: 60_000,
    slowReadEnabled: true,
    slowReadChunkMs: 2_000,
    resetStormEnabled: true,
    honeypotPaths: [          // pure exploit lures — NEVER include app routes like /admin
      '/.env', '/.git/HEAD', '/wp-config.php', '/phpmyadmin',
      '/backup.sql', '/db.sql', '/.aws/credentials',
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
//  STATIC ASSET DETECTOR (Zero-Delay Next.js & Browser Asset Bypass)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if the requested path is a static browser asset.
 * Static assets are bypassed from rate limiting and path counting so page loads are 100% instant.
 */
function isStaticAsset(path) {
  if (!path || typeof path !== 'string') return false;
  const p = path.toLowerCase().split('?')[0];

  if (
    p.startsWith('/_next/') ||
    p.startsWith('/static/') ||
    p.startsWith('/assets/') ||
    p.startsWith('/public/') ||
    p.startsWith('/images/') ||
    p.startsWith('/fonts/') ||
    p === '/favicon.ico' ||
    p === '/robots.txt' ||
    p === '/sitemap.xml'
  ) {
    return true;
  }

  return /\.(js|mjs|cjs|css|png|jpg|jpeg|gif|svg|ico|webp|avif|woff|woff2|ttf|eot|otf|map|json|txt|pdf)$/i.test(p);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

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

function getHeader(req, name) {
  if (!req || !req.headers) return undefined;
  const target = name.toLowerCase();
  if (typeof req.headers.get === 'function') {
    return req.headers.get(target);
  }
  return req.headers[target] || req.headers[name];
}

function normalizeHeaders(req) {
  if (!req || !req.headers) return {};
  if (typeof req.headers.entries === 'function') {
    const obj = {};
    for (const [k, v] of req.headers.entries()) {
      obj[k.toLowerCase()] = v;
    }
    return obj;
  }
  if (typeof req.headers === 'object') {
    const obj = {};
    for (const [k, v] of Object.entries(req.headers)) {
      obj[k.toLowerCase()] = v;
    }
    return obj;
  }
  return {};
}

function extractPathAndUrl(req) {
  let fullUrl = '/';
  if (req.nextUrl && typeof req.nextUrl.pathname === 'string') {
    fullUrl = req.nextUrl.pathname + (req.nextUrl.search || '');
  } else if (typeof req.url === 'string') {
    try {
      if (req.url.startsWith('http://') || req.url.startsWith('https://')) {
        const u = new URL(req.url);
        fullUrl = u.pathname + u.search;
      } else {
        fullUrl = req.url;
      }
    } catch {
      fullUrl = req.url;
    }
  }
  const path = fullUrl.split('?')[0] || '/';
  return { fullUrl, path };
}

function getClientIP(req, trustProxy = true) {
  if (trustProxy) {
    const xff = getHeader(req, 'x-forwarded-for');
    if (xff) return xff.split(',')[0].trim();
    const xrip = getHeader(req, 'x-real-ip');
    if (xrip) return xrip.trim();
    const cfip = getHeader(req, 'cf-connecting-ip');
    if (cfip) return cfip.trim();
  }
  return (
    req.ip ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    '0.0.0.0'
  ).replace(/^::ffff:/, '');
}

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

function randomToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function parseCookies(cookieHeader = '') {
  if (!cookieHeader || typeof cookieHeader !== 'string') return {};
  return cookieHeader.split(';').reduce((acc, pair) => {
    const [k, ...v] = pair.split('=');
    if (k) acc[k.trim()] = v.join('=').trim();
    return acc;
  }, {});
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TELEGRAM NOTIFICATION ENGINE (Vercel & Node.js Ready)
// ═══════════════════════════════════════════════════════════════════════════════

function escapeTelegramHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function sendTelegramAlert(threatInfo, config, log) {
  const tg = config?.telegram || {};
  const botToken = tg.botToken || (typeof process !== 'undefined' ? (process.env.TELEGRAM_BOT_TOKEN || process.env.NEXTGUARD_TELEGRAM_TOKEN) : null);
  const chatId = tg.chatId || (typeof process !== 'undefined' ? (process.env.TELEGRAM_CHAT_ID || process.env.NEXTGUARD_TELEGRAM_CHAT_ID) : null);

  const isEnabled = tg.enabled === true || (tg.enabled !== false && Boolean(botToken && chatId));
  if (!isEnabled || !botToken || !chatId) return false;

  const minLayer = tg.minLayer ?? 1;
  if ((threatInfo.layer ?? 1) < minLayer) return false;

  const cooldownMs = tg.cooldownMs ?? 30_000;
  const key = `${threatInfo.ip || 'unknown'}:${threatInfo.layer || 0}`;
  const now = Date.now();
  const lastAlert = telegramCooldown.get(key) || 0;
  if (now - lastAlert < cooldownMs) {
    return false;
  }
  telegramCooldown.set(key, now);

  const message = [
    `🛡️ <b>[NextGuard] Security Alert</b>`,
    `🧱 <b>Layer:</b> Layer ${threatInfo.layer || 'Unknown'}`,
    `⚠️ <b>Threat:</b> ${escapeTelegramHtml(threatInfo.reason || 'Attack detected')}`,
    `🌐 <b>Target Path:</b> <code>${escapeTelegramHtml(threatInfo.path || '/')}</code>`,
    `📍 <b>Attacker IP:</b> <code>${escapeTelegramHtml(threatInfo.ip || '0.0.0.0')}</code>`,
    `📱 <b>Method:</b> ${escapeTelegramHtml(threatInfo.method || 'GET')}`,
    `⚡ <b>Action:</b> ${escapeTelegramHtml(threatInfo.action || 'BLOCKED')}`,
    `⏰ <b>Timestamp:</b> ${new Date().toISOString()}`,
  ].join('\n');

  const payload = {
    chat_id: chatId,
    text: message,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  };

  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

  try {
    if (typeof fetch === 'function') {
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      return true;
    } else {
      const postData = JSON.stringify(payload);
      const parsedUrl = new URL(url);
      const req = https.request({
        hostname: parsedUrl.hostname,
        port: 443,
        path: parsedUrl.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
        timeout: 4000,
      });
      req.on('error', (err) => log?.debug('Telegram alert error:', err.message));
      req.write(postData);
      req.end();
      return true;
    }
  } catch (err) {
    log?.debug('Telegram notification failed:', err.message);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RESPONSE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

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

function sendResetStorm(res, log) {
  if (res.headersSent || res.writableEnded) return;
  try {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Length', '0');
    res.statusCode = 400;
    for (let i = 0; i < 50; i++) {
      if (!res.writableEnded) res.write('');
    }
    res.end();
  } catch (e) {
    log?.debug('resetStorm error (expected):', e.message);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 1 — IP REPUTATION & BLACKLIST GATE
// ═══════════════════════════════════════════════════════════════════════════════

function layer1_ipReputation(ip, config, log) {
  const cfg = config.layer1;
  if (!cfg.enabled) return { blocked: false };

  if (banlist.has(ip)) {
    const entry = banlist.get(ip);
    if (entry.until === null || entry.until > Date.now()) {
      log.threat(`Layer1 | Banned IP: ${ip} | Reason: ${entry.reason}`);
      return { blocked: true, reason: `IP banned: ${entry.reason}`, layer: 1 };
    } else {
      banlist.delete(ip);
    }
  }

  for (const cidr of cfg.staticBlacklist) {
    if (ipInCIDR(ip, cidr)) {
      log.threat(`Layer1 | Static blacklist hit: ${ip} matches ${cidr}`);
      banlist.set(ip, { until: null, reason: 'static-blacklist' });
      return { blocked: true, reason: 'IP in static blacklist', layer: 1 };
    }
  }

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

  if (now - rec.firstSeen > cfg.windowMs) {
    rec.count = 0;
    rec.firstSeen = now;
    rec.paths = new Set();
  }

  if (now - rec.burstStart > cfg.burstWindowMs) {
    rec.burstCount = 0;
    rec.burstStart = now;
  }

  rec.count++;
  rec.burstCount++;
  rec.lastSeen = now;
  ipStore.set(ip, rec);

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

  const rec = ipStore.get(ip);
  if (!rec) return { blocked: false };

  const { path } = extractPathAndUrl(req);
  rec.paths.add(path);

  if (rec.paths.size > cfg.maxPathsPerWindow) {
    rec.violations++;
    log.threat(`Layer3 | Path scanning detected: ${ip} (${rec.paths.size} unique paths)`);
    return { blocked: true, reason: 'Path scanning behavior detected', layer: 3 };
  }

  if (cfg.jsChallenge) {
    const cookieHeader = getHeader(req, 'cookie') || '';
    const cookies = parseCookies(cookieHeader);
    const fp = cookies[cfg.fingerprintCookieName];
    if (fp) {
      const [token, solution] = decodeURIComponent(fp).split(':');
      if (token && solution && sha256(token + solution).startsWith(POW_PREFIX)) {
        return { blocked: false };
      }
    }
    return { blocked: false, needsChallenge: true };
  }

  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 4 — HEADER & PROTOCOL INTEGRITY CHECK
// ═══════════════════════════════════════════════════════════════════════════════

function layer4_headers(ip, req, config, log) {
  const cfg = config.layer4;
  if (!cfg.enabled) return { blocked: false };

  const allHeaders = normalizeHeaders(req);
  const ua = getHeader(req, 'user-agent') || '';
  const method = (req.method || 'GET').toUpperCase();

  if (cfg.requireUserAgent && !ua) {
    const rec = ipStore.get(ip);
    if (rec) rec.violations++;
    log.warn(`Layer4 | Missing User-Agent: ${ip}`);
    return { blocked: true, reason: 'Missing User-Agent header', layer: 4 };
  }

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

  if (!ALLOWED_METHODS.has(method)) {
    const rec = ipStore.get(ip);
    if (rec) rec.violations++;
    log.warn(`Layer4 | Invalid HTTP method: ${method} from ${ip}`);
    return { blocked: true, reason: `Invalid HTTP method: ${method}`, layer: 4 };
  }

  const headerStr = JSON.stringify(allHeaders);
  if (headerStr.length > cfg.maxHeaderSize) {
    const rec = ipStore.get(ip);
    if (rec) rec.violations++;
    log.warn(`Layer4 | Oversized headers from ${ip}: ${headerStr.length} bytes`);
    return { blocked: true, reason: 'Request headers too large', layer: 4 };
  }

  for (const h of SUSPICIOUS_HEADERS) {
    if (allHeaders[h] !== undefined) {
      const rec = ipStore.get(ip);
      if (rec) rec.violations++;
      log.warn(`Layer4 | Suspicious header "${h}" from ${ip}: ${allHeaders[h]}`);
      return { blocked: true, reason: `Suspicious header detected: ${h}`, layer: 4 };
    }
  }

  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYER 5 — PAYLOAD & BODY INSPECTION (Zero False Positives for Auth)
// ═══════════════════════════════════════════════════════════════════════════════

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

function deepInspect(obj, path = '') {
  if (typeof obj === 'string') {
    const fieldName = (path.split('.').pop() || '').replace(/[\[\]0-9]/g, '').toLowerCase();
    if (SAFE_BODY_FIELDS.has(fieldName)) {
      return { matched: false, pattern: null, path: null };
    }
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
      const fieldName = k.toLowerCase().replace(/[-_]/g, '');
      if (SAFE_BODY_FIELDS.has(fieldName)) {
        continue;
      }
      const r = deepInspect(v, path ? `${path}.${k}` : k);
      if (r.matched) return r;
    }
  }
  return { matched: false, pattern: null, path: null };
}

async function layer5_payload(ip, req, config, log) {
  const cfg = config.layer5;
  if (!cfg.enabled) return { blocked: false };

  const { fullUrl } = extractPathAndUrl(req);

  // Inspect Query String
  if (cfg.inspectQuery && fullUrl.includes('?')) {
    const qs = fullUrl.split('?').slice(1).join('?');
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

  // Inspect Cookies Safely (Skip session/JWT tokens)
  if (cfg.inspectCookies) {
    const cookieHeader = getHeader(req, 'cookie') || '';
    if (cookieHeader) {
      const parsed = parseCookies(cookieHeader);
      for (const [cName, cVal] of Object.entries(parsed)) {
        const lowerName = cName.toLowerCase();
        if (
          SAFE_BODY_FIELDS.has(lowerName) ||
          SAFE_COOKIE_PREFIXES.some((p) => lowerName.startsWith(p)) ||
          lowerName.includes('token') ||
          lowerName.includes('session')
        ) {
          continue;
        }
        const result = inspectValue(cVal);
        if (result.matched) {
          const rec = ipStore.get(ip);
          if (rec) rec.violations += 3;
          log.threat(`Layer5 | Attack in cookie "${cName}" from ${ip}: ${result.pattern}`);
          return { blocked: true, reason: `Malicious payload in cookie: ${cName}`, layer: 5 };
        }
      }
    }
  }

  // Inspect Custom Request Headers (Exempt browser standard headers)
  if (cfg.inspectHeaders) {
    const allHeaders = normalizeHeaders(req);
    for (const [hk, hv] of Object.entries(allHeaders)) {
      if (SAFE_HEADERS.has(hk)) continue;
      const result = inspectValue(String(hv));
      if (result.matched) {
        const rec = ipStore.get(ip);
        if (rec) rec.violations += 2;
        log.threat(`Layer5 | Attack in header "${hk}" from ${ip}`);
        return { blocked: true, reason: `Malicious payload in header: ${hk}`, layer: 5 };
      }
    }
  }

  // Inspect Body (Only for POST/PUT/PATCH, safely skipping passwords and hashes)
  if (cfg.inspectBody && ['POST', 'PUT', 'PATCH'].includes((req.method || '').toUpperCase())) {
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
//  LAYER 7 — ACTIVE COUNTER-STRIKE & TARPIT ENGINE (Safe for Vercel/Serverless)
// ═══════════════════════════════════════════════════════════════════════════════

function isHoneypotPath(url, honeypotPaths) {
  if (!honeypotPaths || !Array.isArray(honeypotPaths) || honeypotPaths.length === 0) return false;
  const path = (url.split('?')[0] || '').toLowerCase();
  return honeypotPaths.some((p) => {
    const target = (p || '').toLowerCase();
    if (!target) return false;
    return path === target || path.startsWith(target.endsWith('/') ? target : target + '/');
  });
}

async function layer7_counterStrike(ip, req, res, config, log, reason) {
  const cfg = config.layer7;
  if (!cfg.enabled) return { handled: false };

  const isServerless = !res || res.isMock === true;
  const { path } = extractPathAndUrl(req);
  const isHoneypot = isHoneypotPath(path, cfg.honeypotPaths);

  if (isHoneypot) {
    log.threat(`Layer7 | Honeypot triggered by ${ip} → ${path}`);
    const rec = ipStore.get(ip);
    if (rec) rec.violations += 5;

    // On serverless/Edge, reject immediately without hanging execution
    if (isServerless) {
      return { handled: false };
    }
    if (cfg.tarpitEnabled && res && typeof res.write === 'function') {
      await sendTarpit(res, cfg.tarpitMaxMs, cfg.slowReadChunkMs, log);
      return { handled: true };
    }
  }

  // Tarpit on raw Node.js servers only
  if (!isServerless && cfg.tarpitEnabled && tarpitStore.has(ip) && res && typeof res.write === 'function') {
    const until = tarpitStore.get(ip);
    if (until > Date.now()) {
      log.debug(`Layer7 | Tarpitting ${ip} for ${Math.ceil((until - Date.now()) / 1000)}s`);
      await sendTarpit(res, until - Date.now(), cfg.slowReadChunkMs, log);
      return { handled: true };
    } else {
      tarpitStore.delete(ip);
    }
  }

  const rec = ipStore.get(ip);
  const violations = rec?.violations || 0;

  if (violations >= 3) {
    tarpitStore.set(ip, Date.now() + cfg.tarpitDelayMs);
    log.threat(`Layer7 | Attacker penalized: ${ip} (${violations} violations) — reason: ${reason}`);

    if (!isServerless && cfg.tarpitEnabled && res && typeof res.write === 'function') {
      await sendTarpit(res, cfg.tarpitDelayMs, cfg.slowReadChunkMs, log);
      return { handled: true };
    }
  }

  if (!isServerless && violations >= 1 && cfg.resetStormEnabled && res && typeof res.write === 'function') {
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
      const status = document.getElementById('status');
      const bar = document.getElementById('bar');
      let i = 0;
      const hash = async (s) => {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
        return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
      };
      status.textContent = 'Solving challenge…';
      while (true) {
        if (i % 500 === 0) {
          bar.style.width = Math.min(90, i / 2000 * 100) + '%';
          status.textContent = 'Checking ' + i + ' candidates…';
          await new Promise(r => setTimeout(r, 0));
        }
        const h = await hash(challenge + i);
        if (h.startsWith(prefix)) {
          bar.style.width = '100%';
          status.textContent = 'Verified! Reloading…';
          document.cookie = '__ng_fp=' + encodeURIComponent(challenge + ':' + i) + '; path=/; max-age=86400; SameSite=Lax';
          window.location.reload();
          return;
        }
        i++;
      }
    })();
  </script>
</body>
</html>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SECURITY HEADERS
// ═══════════════════════════════════════════════════════════════════════════════

function applySecurityHeaders(res) {
  if (!res || typeof res.setHeader !== 'function') return;
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
//  OPTIONAL ADMIN ROUTES (Only when developer explicitly enables config.admin)
// ═══════════════════════════════════════════════════════════════════════════════

function handleAdminRoute(path, req, res, config, log, prefix) {
  const method = (req.method || 'GET').toUpperCase();

  if (path === `${prefix}/stats` && method === 'GET') {
    sendResponse(res, 200, {
      version: VERSION,
      uptime: typeof process !== 'undefined' ? process.uptime() : 0,
      trackedIPs: ipStore.size,
      bannedIPs: banlist.size,
      tarpittedIPs: tarpitStore.size,
      challengesSent: challengeStore.size,
      mode: config.mode,
    });
    return true;
  }

  if (path === `${prefix}/ban` && method === 'POST') {
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

  if (path === `${prefix}/unban` && method === 'POST') {
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
//  MEMORY CLEANUP
// ═══════════════════════════════════════════════════════════════════════════════

function startCleanupJob(config) {
  if (typeof setInterval !== 'function') return;
  const CLEANUP_INTERVAL = 5 * 60 * 1000;
  const MAX_IDLE_MS = config.layer2.windowMs * 2;

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, rec] of ipStore) {
      if (now - rec.lastSeen > MAX_IDLE_MS) ipStore.delete(ip);
    }
    for (const [ip, ban] of banlist) {
      if (ban.until !== null && ban.until < now) banlist.delete(ip);
    }
    for (const [ip, until] of tarpitStore) {
      if (until < now) tarpitStore.delete(ip);
    }
    for (const [token, ch] of challengeStore) {
      if (ch.expires < now) challengeStore.delete(token);
    }
    for (const [k, time] of telegramCooldown) {
      if (now - time > 120_000) telegramCooldown.delete(k);
    }
    if (Math.random() < 0.083) geoCache.clear();
  }, CLEANUP_INTERVAL);

  if (typeof timer.unref === 'function') timer.unref();
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CORE 7-LAYER GUARD ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

async function runGuard(req, res, config, log, events) {
  const ip = getClientIP(req, config.trustProxy);
  const { path } = extractPathAndUrl(req);
  const method = (req.method || 'GET').toUpperCase();

  // ── FAST-PATH: Static Asset Bypass ─────────────────────────────────────────
  // Next.js chunks, css, fonts, images, and webpack bundles are allowed immediately in 0ms!
  // They do not consume rate limit or behavioral fuzzer limits.
  if (isStaticAsset(path)) {
    if (res) applySecurityHeaders(res);
    return { blocked: false };
  }

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

  log.debug(`Guard | ${ip} ${method} ${path}`);

  const reportThreat = (layer, reason, action = 'BLOCKED') => {
    const threatData = {
      ip,
      layer,
      reason,
      path,
      method,
      action,
      req,
      timestamp: new Date().toISOString(),
    };
    events.emit('threat', threatData);
    sendTelegramAlert(threatData, config, log).catch(() => {});
  };

  // Optional Admin routes (strictly opt-in, disabled by default)
  if (config.admin && config.admin.enabled) {
    const prefix = config.admin.routePrefix || '/__nextguard';
    if (path.startsWith(prefix)) {
      if (handleAdminRoute(path, req, res, config, log, prefix)) return { blocked: false };
    }
  }

  // Lockdown mode — emergency traffic stop
  if (config.mode === 'lockdown') {
    log.warn(`Lockdown | Blocking all traffic: ${ip}`);
    reportThreat(0, 'Lockdown mode active', '503 SERVICE UNAVAILABLE');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, 'lockdown');
    if (!l7.handled && res) sendResponse(res, 503, { error: 'Service unavailable' });
    return { blocked: true, reason: 'Lockdown mode active', layer: 0 };
  }

  // ── Layer 1: IP Reputation ──────────────────────────────────────────────
  const r1 = layer1_ipReputation(ip, config, log);
  if (r1.blocked) {
    reportThreat(1, r1.reason, '403 FORBIDDEN');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r1.reason);
    if (!l7.handled && res) sendResponse(res, 403, { error: 'Access denied', reason: r1.reason, layer: 1 });
    return { blocked: true, ...r1 };
  }

  // ── Layer 2: Rate Limiting & Burst Protection ───────────────────────────
  const r2 = layer2_rateLimiter(ip, config, log);
  if (r2.blocked) {
    reportThreat(2, r2.reason, '429 TOO MANY REQUESTS');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r2.reason);
    if (!l7.handled && res) {
      sendResponse(res, 429, { error: 'Too Many Requests', reason: r2.reason, layer: 2 }, {
        'Retry-After': String(r2.retryAfter || 60),
      });
    }
    return { blocked: true, ...r2 };
  }

  // ── Layer 3: Behavioral Anomaly Detection ───────────────────────────────
  const r3 = layer3_behavior(ip, req, config, log);
  if (r3.blocked) {
    reportThreat(3, r3.reason, '403 FORBIDDEN');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r3.reason);
    if (!l7.handled && res) sendResponse(res, 403, { error: 'Access denied', reason: r3.reason, layer: 3 });
    return { blocked: true, ...r3 };
  }

  // JS Proof-of-Work Challenge (optional)
  if (r3.needsChallenge && config.layer3.jsChallenge) {
    const token = randomToken();
    const nonce = randomToken(8);
    challengeStore.set(token, { token, expires: Date.now() + 120_000, solved: false, ip });
    if (res) {
      sendResponse(res, 403, generateChallengePage(token, nonce), {
        'Content-Type': 'text/html; charset=utf-8',
      });
    }
    return { blocked: true, reason: 'JS challenge issued', layer: 3 };
  }

  // ── Layer 4: Header & Protocol Integrity ────────────────────────────────
  const r4 = layer4_headers(ip, req, config, log);
  if (r4.blocked) {
    reportThreat(4, r4.reason, '400 BAD REQUEST');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r4.reason);
    if (!l7.handled && res) sendResponse(res, 400, { error: 'Bad Request', reason: r4.reason, layer: 4 });
    return { blocked: true, ...r4 };
  }

  // ── Layer 5: Payload Inspection ─────────────────────────────────────────
  const r5 = await layer5_payload(ip, req, config, log);
  if (r5.blocked) {
    reportThreat(5, r5.reason, '400 BAD REQUEST');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r5.reason);
    if (!l7.handled && res) sendResponse(res, 400, { error: 'Malicious payload detected', reason: r5.reason, layer: 5 });
    return { blocked: true, ...r5 };
  }

  // ── Layer 6: Geo-Fencing & ASN ──────────────────────────────────────────
  const r6 = await layer6_geo(ip, config, log);
  if (r6.blocked) {
    reportThreat(6, r6.reason, '403 FORBIDDEN');
    if (res) sendResponse(res, 403, { error: 'Access denied', reason: r6.reason, layer: 6 });
    return { blocked: true, ...r6 };
  }

  // ── Layer 7: Honeypot Probing Check ─────────────────────────────────────
  const cfg7 = config.layer7;
  if (cfg7.enabled && isHoneypotPath(path, cfg7.honeypotPaths)) {
    reportThreat(7, 'Honeypot access', 'TARPIT COUNTER-STRIKE');
    await layer7_counterStrike(ip, req, res, config, log, 'Honeypot access');
    return { blocked: true, reason: 'Honeypot access', layer: 7 };
  }

  // ── All 7 layers cleared — Apply security headers ───────────────────────
  if (res) applySecurityHeaders(res);
  log.debug(`Guard | ALLOW ${ip} ${method} ${path}`);
  return { blocked: false };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  FACTORY: createNextGuard(config?)
// ═══════════════════════════════════════════════════════════════════════════════

function createNextGuard(userConfig = {}) {
  const config = deepMerge(DEFAULT_CONFIG, userConfig);
  const log = createLogger(config.logLevel);
  const events = new EventEmitter();

  log.info(`NextGuard v${VERSION} initialized | mode: ${config.mode} | layers: 1-7`);
  startCleanupJob(config);

  // Express / Node.js HTTP Middleware
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

  // Next.js (App Router / Edge / Vercel) Middleware
  const nextMiddleware = async (req) => {
    let statusCode = 200;
    let responseBody = null;
    const responseHeaders = {
      'Content-Type': 'application/json',
      'X-NextGuard': VERSION,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    };

    const mockRes = {
      isMock: true, // Identifies serverless/Next.js so tarpit does not cause 10-second freeze
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
      const body = responseBody || JSON.stringify({
        error: 'Access denied',
        reason: result.reason,
        layer: result.layer,
      });
      return new Response(body, {
        status: statusCode || 403,
        headers: responseHeaders,
      });
    }

    return null;
  };

  // Universal Middleware: handles both Express (req, res, next) and Next.js (req)
  const universalMiddleware = (req, res, next) => {
    if (typeof next === 'function' || (res && typeof res.setHeader === 'function' && typeof res.end === 'function')) {
      return middleware(req, res, next);
    }
    return nextMiddleware(req);
  };

  const handler = (next) => (req, res) => {
    runGuard(req, res, config, log, events).then((result) => {
      if (!result.blocked) next(req, res);
    }).catch((err) => {
      log.error('Guard error:', err);
      next(req, res);
    });
  };

  const ban = (ip, { durationMs = null, reason = 'manual' } = {}) => {
    banlist.set(ip, { until: durationMs ? Date.now() + durationMs : null, reason });
    log.info(`API | Ban: ${ip} (${reason})`);
  };

  const unban = (ip) => {
    banlist.delete(ip);
    tarpitStore.delete(ip);
    log.info(`API | Unban: ${ip}`);
  };

  const getStats = () => ({
    version: VERSION,
    uptime: typeof process !== 'undefined' ? process.uptime() : 0,
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

  const setMode = (mode) => {
    if (!['protect', 'monitor', 'lockdown'].includes(mode)) {
      throw new Error(`Invalid mode: ${mode}. Must be protect | monitor | lockdown`);
    }
    config.mode = mode;
    log.info(`Mode changed → ${mode}`);
  };

  const addToBlacklist = (ip) => {
    config.layer1.staticBlacklist.push(ip);
    log.info(`API | Blacklist added: ${ip}`);
  };

  const removeFromBlacklist = (ip) => {
    config.layer1.staticBlacklist = config.layer1.staticBlacklist.filter((i) => i !== ip);
    log.info(`API | Blacklist removed: ${ip}`);
  };

  universalMiddleware.instance = null;
  universalMiddleware.middleware = middleware;
  universalMiddleware.nextMiddleware = nextMiddleware;
  universalMiddleware.handler = handler;
  universalMiddleware.ban = ban;
  universalMiddleware.unban = unban;
  universalMiddleware.getStats = getStats;
  universalMiddleware.setMode = setMode;
  universalMiddleware.addToBlacklist = addToBlacklist;
  universalMiddleware.removeFromBlacklist = removeFromBlacklist;
  universalMiddleware.events = events;
  universalMiddleware.config = config;
  universalMiddleware.version = VERSION;

  const instance = {
    middleware,
    nextMiddleware,
    universalMiddleware,
    handler,
    ban,
    unban,
    getStats,
    setMode,
    addToBlacklist,
    removeFromBlacklist,
    sendTelegramAlert: (threatInfo) => sendTelegramAlert(threatInfo, config, log),
    events,
    config,
    version: VERSION,
  };

  universalMiddleware.instance = instance;
  return instance;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PRIMARY EXPORT: nextguard(...)
// ═══════════════════════════════════════════════════════════════════════════════

function isRequestObject(obj) {
  return Boolean(
    obj &&
    typeof obj === 'object' &&
    typeof obj.method === 'string' &&
    (typeof obj.url === 'string' || obj.nextUrl)
  );
}

let _defaultInstance = null;
function getOrCreateDefaultInstance() {
  if (!_defaultInstance) {
    _defaultInstance = createNextGuard();
  }
  return _defaultInstance;
}

function nextguard(optionsOrRequest = {}) {
  if (isRequestObject(optionsOrRequest)) {
    const inst = getOrCreateDefaultInstance();
    return inst.universalMiddleware(optionsOrRequest);
  }

  const instance = createNextGuard(optionsOrRequest);
  return instance.universalMiddleware;
}

const defaultInst = getOrCreateDefaultInstance();

nextguard.nextguard = nextguard;
nextguard.createNextGuard = createNextGuard;
nextguard.middleware = defaultInst.universalMiddleware;
nextguard.nextMiddleware = defaultInst.nextMiddleware;
nextguard.handler = defaultInst.handler;
nextguard.ban = defaultInst.ban;
nextguard.unban = defaultInst.unban;
nextguard.getStats = defaultInst.getStats;
nextguard.setMode = defaultInst.setMode;
nextguard.addToBlacklist = defaultInst.addToBlacklist;
nextguard.removeFromBlacklist = defaultInst.removeFromBlacklist;
nextguard.events = defaultInst.events;
nextguard.sendTelegramAlert = (threatInfo, cfg = {}) => sendTelegramAlert(threatInfo, deepMerge(DEFAULT_CONFIG, cfg), createLogger('silent'));
nextguard.getClientIP = getClientIP;
nextguard.inspectValue = inspectValue;
nextguard.deepInspect = deepInspect;
nextguard.ipInCIDR = ipInCIDR;
nextguard.VERSION = VERSION;

module.exports = nextguard;
