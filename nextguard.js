'use strict';

const crypto = require('crypto');
const { EventEmitter } = require('events');
const http = require('http');
const https = require('https');
const net = require('net');

const {
  checkDdos,
  cleanupDdosStore,
} = require('./security/ddos');

const {
  inspectValue,
  deepInspect,
  SAFE_BODY_FIELDS,
} = require('./security/waf');

const {
  sendTarpit,
  sendResetStorm,
  isHoneypotPath,
  cleanupTarpitStore,
  tarpitStore,
} = require('./security/counter');

const {
  checkIpGate,
  ipInCIDR,
  banIp,
  unbanIp,
  getBannedCount,
  cleanupBanlist,
  banlist,
  checkBot,
  MALICIOUS_UA_PATTERNS,
} = require('./security/reputation');

const {
  sendTelegramAlert,
  cleanupTelegramCooldown,
} = require('./security/telegram');

const VERSION = '1.3.1';

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
  'sec-ch-ua-arch',
  'sec-ch-ua-bitness',
  'sec-ch-ua-full-version',
  'sec-ch-ua-full-version-list',
  'sec-ch-ua-model',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-fetch-user',
  'referer',
  'origin',
  'host',
  'connection',
  'keep-alive',
  'upgrade-insecure-requests',
  'cache-control',
  'pragma',
  'te',
  'content-type',
  'content-length',
  'content-encoding',
  'transfer-encoding',
  'next-action',
  'next-router-prefetch',
  'next-router-state-tree',
  'next-url',
  'rsc',
  'purpose',
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'x-forwarded-port',
  'x-real-ip',
  'x-request-id',
  'x-correlation-id',
  'x-vercel-id',
  'x-vercel-deployment-url',
  'x-vercel-forwarded-for',
  'x-vercel-ip-city',
  'x-vercel-ip-country',
  'x-vercel-ip-country-region',
  'x-vercel-ip-latitude',
  'x-vercel-ip-longitude',
  'x-vercel-proxied-for',
  'cf-connecting-ip',
  'cf-connecting-ipv6',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'cf-cache-status',
  'cf-request-id',
  'cf-worker',
  'cdn-loop',
  'fly-forwarded-port',
  'fly-client-ip',
  'traceparent',
  'tracestate',
  'baggage',
  'via',
]);

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
  '__cf_bm',
  '__cfruid',
  '_vercel',
  'vercel',
];

const SUSPICIOUS_HEADERS = [
  'x-original-url',
  'x-rewrite-url',
  'x-override-url',
  'x-http-method-override',
  'x-method-override',
];

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

const ipStore = new Map();
const challengeStore = new Map();
const geoCache = new Map();

const DEFAULT_CONFIG = {
  name: 'NextGuard',
  mode: 'protect',
  trustProxy: true,
  logLevel: 'warn',
  blockPage: null,

  telegram: {
    enabled: false,
    botToken: null,
    chatId: null,
    cooldownMs: 30000,
    minLayer: 1,
  },

  admin: {
    enabled: false,
    routePrefix: '/__nextguard',
  },

  layer1: {
    enabled: true,
    staticBlacklist: [],
    autobanOnViolations: 5,
    banDurationMs: 3600000,
  },

  layer2: {
    enabled: true,
    windowMs: 60000,
    maxRequests: 360,
    burstLimit: 80,
    burstWindowMs: 5000,
    penaltyMs: 30000,
  },

  layer3: {
    enabled: true,
    maxPathsPerWindow: 250,
    maxErrorsPerWindow: 30,
    fingerprintCookieName: '__ng_fp',
    jsChallenge: false,
  },

  layer4: {
    enabled: true,
    requireUserAgent: false,
    blockMaliciousUA: true,
    blockMissingSNI: false,
    maxHeaderSize: 32768,
  },

  layer5: {
    enabled: true,
    maxBodySize: 2097152,
    inspectQuery: true,
    inspectBody: true,
    inspectCookies: true,
    inspectHeaders: true,
  },

  layer6: {
    enabled: false,
    allowedCountries: [],
    blockedCountries: [],
    geoApiUrl: null,
  },

  layer7: {
    enabled: true,
    tarpitEnabled: true,
    tarpitDelayMs: 10000,
    tarpitMaxMs: 60000,
    slowReadEnabled: true,
    slowReadChunkMs: 2000,
    resetStormEnabled: true,
    honeypotPaths: [
      '/.env', '/.git/head', '/wp-config.php', '/phpmyadmin',
      '/backup.sql', '/db.sql', '/.aws/credentials',
    ],
  },
};

const LOG_LEVELS = { silent: 0, warn: 1, info: 2, debug: 3 };

function createLogger(level) {
  const lvl = LOG_LEVELS[level] ?? 1;
  const ts = () => new Date().toISOString();
  const prefix = '[NextGuard]';
  return {
    warn:  (...a) => lvl >= 1 && console.warn(`\x1b[33m${prefix}[WARN]\x1b[0m ${ts()}`, ...a),
    info:  (...a) => lvl >= 2 && console.info(`\x1b[36m${prefix}[INFO]\x1b[0m ${ts()}`, ...a),
    debug: (...a) => lvl >= 3 && console.debug(`\x1b[90m${prefix}[DEBUG]\x1b[0m ${ts()}`, ...a),
    error: (...a) => console.error(`\x1b[31m${prefix}[ERROR]\x1b[0m ${ts()}`, ...a),
    threat:(...a) => console.error(`\x1b[41m\x1b[97m${prefix}[THREAT]\x1b[0m ${ts()}`, ...a),
  };
}

const INTERNAL_BYPASS_PATHS = new Set([
  '/blocked',
  '/403',
  '/429',
  '/503',
  '/error',
  '/access-denied',
  '/too-many-requests',
  '/rate-limited',
]);

function isStaticAsset(path) {
  if (!path || typeof path !== 'string') return false;
  const p = path.toLowerCase().split('?')[0];

  if (INTERNAL_BYPASS_PATHS.has(p)) return true;

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

function sendResponse(res, statusCode, body, headers = {}) {
  if (!res || res.headersSent || res.writableEnded) return;

  const defaultHeaders = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-NextGuard': VERSION,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'no-store',
  };

  Object.entries({ ...defaultHeaders, ...headers }).forEach(([k, v]) => {
    try { res.setHeader(k, v); } catch {}
  });

  try {
    res.statusCode = statusCode;
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  } catch {}
}

function applySecurityHeaders(res) {
  if (!res || typeof res.setHeader !== 'function') return;
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-NextGuard': VERSION,
  };
  for (const [k, v] of Object.entries(headers)) {
    try { res.setHeader(k, v); } catch {}
  }
}

function layer1_ipReputation(ip, config, log) {
  return checkIpGate(ip, config.layer1, log);
}

function layer2_rateLimiter(ip, config, log) {
  return checkDdos(ip, config.layer2, log);
}

function layer3_behavior(ip, req, config, log) {
  const cfg = config.layer3;
  if (!cfg.enabled) return { blocked: false };

  const rec = ipStore.get(ip);
  if (!rec) return { blocked: false };

  const isPrefetch = (
    getHeader(req, 'next-router-prefetch') === '1' ||
    getHeader(req, 'purpose') === 'prefetch' ||
    getHeader(req, 'sec-purpose') === 'prefetch' ||
    getHeader(req, 'x-middleware-prefetch') === '1'
  );

  const { path } = extractPathAndUrl(req);

  if (!isPrefetch) {
    rec.paths.add(path);
  }

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
      if (token && solution && sha256(token + solution).startsWith('000')) {
        return { blocked: false };
      }
    }
    return { blocked: false, needsChallenge: true };
  }

  return { blocked: false };
}

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
    const botResult = checkBot(ua);
    if (botResult.isBot) {
      const rec = ipStore.get(ip);
      if (rec) rec.violations += 2;
      log.threat(`Layer4 | Malicious UA blocked: ${ip} -> "${ua}"`);
      return { blocked: true, reason: `Malicious user agent detected: ${ua}`, layer: 4 };
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

async function layer5_payload(ip, req, config, log) {
  const cfg = config.layer5;
  if (!cfg.enabled) return { blocked: false };

  const { fullUrl } = extractPathAndUrl(req);

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

async function layer7_counterStrike(ip, req, res, config, log, reason) {
  const cfg = config.layer7;
  if (!cfg.enabled) return { handled: false };

  const isServerless = !res || res.isMock === true;
  const { path } = extractPathAndUrl(req);
  const isHoneypot = isHoneypotPath(path, cfg.honeypotPaths);

  if (isHoneypot) {
    log.threat(`Layer7 | Honeypot triggered by ${ip} -> ${path}`);
    const rec = ipStore.get(ip);
    if (rec) rec.violations += 5;

    if (isServerless) {
      return { handled: false };
    }
    if (cfg.tarpitEnabled && res && typeof res.write === 'function') {
      await sendTarpit(res, cfg.tarpitMaxMs, cfg.slowReadChunkMs, log);
      return { handled: true };
    }
  }

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

function generateChallengePage(token) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Security Check</title></head><body><div style="text-align:center;padding:50px;font-family:sans-serif"><h2>Security Verification</h2><p>Verifying browser...</p></div><script>(async()=>{const t=${JSON.stringify(token)};let i=0;while(true){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t+i));const h=Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');if(h.startsWith('000')){document.cookie='__ng_fp='+encodeURIComponent(t+':'+i)+';path=/;max-age=86400;SameSite=Lax';window.location.reload();return;}i++;}})();</script></body></html>`;
}

function handleAdminRoute(path, req, res, config, log, prefix) {
  const method = (req.method || 'GET').toUpperCase();

  if (path === `${prefix}/stats` && method === 'GET') {
    sendResponse(res, 200, {
      version: VERSION,
      uptime: typeof process !== 'undefined' ? process.uptime() : 0,
      trackedIPs: ipStore.size,
      bannedIPs: getBannedCount(),
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
      banIp(targetIp, { durationMs, reason });
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
      unbanIp(targetIp);
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

function startCleanupJob(config) {
  if (typeof setInterval !== 'function') return;
  const CLEANUP_INTERVAL = 5 * 60 * 1000;
  const MAX_IDLE_MS = config.layer2.windowMs * 2;

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, rec] of ipStore) {
      if (now - rec.lastSeen > MAX_IDLE_MS) ipStore.delete(ip);
    }
    cleanupBanlist();
    cleanupTarpitStore();
    cleanupDdosStore(MAX_IDLE_MS);
    cleanupTelegramCooldown();

    for (const [token, ch] of challengeStore) {
      if (ch.expires < now) challengeStore.delete(token);
    }
    if (Math.random() < 0.083) geoCache.clear();
  }, CLEANUP_INTERVAL);

  if (typeof timer.unref === 'function') timer.unref();
}

async function runGuard(req, res, config, log, events) {
  const ip = getClientIP(req, config.trustProxy);
  const { path } = extractPathAndUrl(req);
  const method = (req.method || 'GET').toUpperCase();

  if (isStaticAsset(path)) {
    if (res) applySecurityHeaders(res);
    return { blocked: false };
  }

  if (config.blockPage && typeof config.blockPage === 'string') {
    const bp = config.blockPage.toLowerCase().split('?')[0];
    if (path.toLowerCase() === bp || path.toLowerCase().startsWith(bp + '/') || path.toLowerCase().startsWith(bp + '?')) {
      if (res) applySecurityHeaders(res);
      return { blocked: false };
    }
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

  if (config.admin && config.admin.enabled) {
    const prefix = config.admin.routePrefix || '/__nextguard';
    if (path.startsWith(prefix)) {
      if (handleAdminRoute(path, req, res, config, log, prefix)) return { blocked: false };
    }
  }

  if (config.mode === 'lockdown') {
    log.warn(`Lockdown | Blocking all traffic: ${ip}`);
    reportThreat(0, 'Lockdown mode active', '503 SERVICE UNAVAILABLE');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, 'lockdown');
    if (!l7.handled && res) sendResponse(res, 503, { error: 'Service unavailable' });
    return { blocked: true, reason: 'Lockdown mode active', layer: 0 };
  }

  const r1 = layer1_ipReputation(ip, config, log);
  if (r1.blocked) {
    reportThreat(1, r1.reason, '403 FORBIDDEN');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r1.reason);
    if (!l7.handled && res) sendResponse(res, 403, { error: 'Access denied', reason: r1.reason, layer: 1 });
    return { blocked: true, ...r1 };
  }

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

  const r3 = layer3_behavior(ip, req, config, log);
  if (r3.blocked) {
    reportThreat(3, r3.reason, '403 FORBIDDEN');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r3.reason);
    if (!l7.handled && res) sendResponse(res, 403, { error: 'Access denied', reason: r3.reason, layer: 3 });
    return { blocked: true, ...r3 };
  }

  if (r3.needsChallenge && config.layer3.jsChallenge) {
    const token = randomToken();
    challengeStore.set(token, { token, expires: Date.now() + 120000, solved: false, ip });
    if (res) {
      sendResponse(res, 403, generateChallengePage(token), {
        'Content-Type': 'text/html; charset=utf-8',
      });
    }
    return { blocked: true, reason: 'JS challenge issued', layer: 3 };
  }

  const r4 = layer4_headers(ip, req, config, log);
  if (r4.blocked) {
    reportThreat(4, r4.reason, '400 BAD REQUEST');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r4.reason);
    if (!l7.handled && res) sendResponse(res, 400, { error: 'Bad Request', reason: r4.reason, layer: 4 });
    return { blocked: true, ...r4 };
  }

  const r5 = await layer5_payload(ip, req, config, log);
  if (r5.blocked) {
    reportThreat(5, r5.reason, '400 BAD REQUEST');
    const l7 = await layer7_counterStrike(ip, req, res, config, log, r5.reason);
    if (!l7.handled && res) sendResponse(res, 400, { error: 'Malicious payload detected', reason: r5.reason, layer: 5 });
    return { blocked: true, ...r5 };
  }

  const r6 = await layer6_geo(ip, config, log);
  if (r6.blocked) {
    reportThreat(6, r6.reason, '403 FORBIDDEN');
    if (res) sendResponse(res, 403, { error: 'Access denied', reason: r6.reason, layer: 6 });
    return { blocked: true, ...r6 };
  }

  const cfg7 = config.layer7;
  if (cfg7.enabled && isHoneypotPath(path, cfg7.honeypotPaths)) {
    reportThreat(7, 'Honeypot access', 'TARPIT COUNTER-STRIKE');
    await layer7_counterStrike(ip, req, res, config, log, 'Honeypot access');
    return { blocked: true, reason: 'Honeypot access', layer: 7 };
  }

  if (res) applySecurityHeaders(res);
  log.debug(`Guard | ALLOW ${ip} ${method} ${path}`);
  return { blocked: false };
}

function createNextGuard(userConfig = {}) {
  const config = deepMerge(DEFAULT_CONFIG, userConfig);
  const log = createLogger(config.logLevel);
  const events = new EventEmitter();

  log.info(`NextGuard v${VERSION} initialized | mode: ${config.mode} | layers: 1-7`);
  startCleanupJob(config);

  const middleware = (req, res, next) => {
    try {
      runGuard(req, res, config, log, events).then((result) => {
        if (!result.blocked && typeof next === 'function') {
          next();
        }
      }).catch((err) => {
        log.error('Guard error:', err);
        if (typeof next === 'function') next();
      });
    } catch (err) {
      log.error('Guard synchronous error:', err);
      if (typeof next === 'function') next();
    }
  };

  const nextMiddleware = async (req) => {
    try {
      let statusCode = 200;
      let responseBody = null;
      const responseHeaders = {
        'Content-Type': 'application/json',
        'X-NextGuard': VERSION,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
      };

      const mockRes = {
        isMock: true,
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
    } catch (err) {
      log.error('Next.js Guard error (fail-safe bypass):', err);
      return null;
    }
  };

  const universalMiddleware = (req, res, next) => {
    if (typeof next === 'function' || (res && typeof res.setHeader === 'function' && typeof res.end === 'function')) {
      return middleware(req, res, next);
    }
    return nextMiddleware(req);
  };

  const handler = (next) => (req, res) => {
    try {
      runGuard(req, res, config, log, events).then((result) => {
        if (!result.blocked) next(req, res);
      }).catch((err) => {
        log.error('Guard error:', err);
        next(req, res);
      });
    } catch (err) {
      log.error('Guard handler error:', err);
      next(req, res);
    }
  };

  const ban = (ip, { durationMs = null, reason = 'manual' } = {}) => {
    banIp(ip, { durationMs, reason });
    log.info(`API | Ban: ${ip} (${reason})`);
  };

  const unban = (ip) => {
    unbanIp(ip);
    tarpitStore.delete(ip);
    log.info(`API | Unban: ${ip}`);
  };

  const getStats = () => ({
    version: VERSION,
    uptime: typeof process !== 'undefined' ? process.uptime() : 0,
    mode: config.mode,
    trackedIPs: ipStore.size,
    bannedIPs: getBannedCount(),
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
    log.info(`Mode changed -> ${mode}`);
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
