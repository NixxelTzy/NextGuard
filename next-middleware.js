'use strict';

const { createNextGuard } = require('./nextguard');

const RATE_STORE = new Map();
const AUTH_FAILS = new Map();

let _cleanupCounter = 0;

function maybeCleanup() {
  _cleanupCounter++;
  if (_cleanupCounter % 500 !== 0) return;
  const now = Date.now();
  for (const [k, v] of RATE_STORE) {
    if (now - v.windowStart > 300000) RATE_STORE.delete(k);
  }
  for (const [k, v] of AUTH_FAILS) {
    if (v.lockUntil < now && v.fails < 3) AUTH_FAILS.delete(k);
  }
}

function checkRateLimit(ip, tier, limits) {
  maybeCleanup();
  const cfg = limits[tier] || limits.api;
  const key = `${ip}:${tier}`;
  const now = Date.now();
  let win = RATE_STORE.get(key);
  if (!win || now - win.windowStart >= cfg.windowMs) {
    win = { count: 1, windowStart: now, strikes: win ? win.strikes : 0 };
    RATE_STORE.set(key, win);
    return { allowed: true, remaining: cfg.max - 1, resetMs: now + cfg.windowMs, strikes: win.strikes };
  }
  win.count++;
  const allowed = win.count <= cfg.max;
  if (!allowed) win.strikes++;
  return {
    allowed,
    remaining: Math.max(0, cfg.max - win.count),
    resetMs: win.windowStart + cfg.windowMs,
    strikes: win.strikes,
  };
}

function checkBruteForce(ip, cfg) {
  const now = Date.now();
  const rec = AUTH_FAILS.get(ip);
  if (!rec) return { blocked: false, remainingSec: 0 };
  if (rec.lockUntil > now) {
    return { blocked: true, remainingSec: Math.ceil((rec.lockUntil - now) / 1000) };
  }
  AUTH_FAILS.delete(ip);
  return { blocked: false, remainingSec: 0 };
}

function recordAuthFail(ip, cfg) {
  const now = Date.now();
  const rec = AUTH_FAILS.get(ip) || { fails: 0, lockUntil: 0 };
  rec.fails++;
  if (rec.fails >= cfg.maxFails) rec.lockUntil = now + cfg.lockoutMs;
  AUTH_FAILS.set(ip, rec);
}

function getIp(request, headers) {
  for (const h of headers) {
    const v = request.headers.get(h);
    if (v) return v.split(',')[0].trim();
  }
  return 'unknown';
}

function isBrowserRequest(request, apiPrefix) {
  const path = new URL(request.url).pathname;
  if (path.startsWith(apiPrefix)) return false;
  const accept = request.headers.get('accept') || '';
  const dest = request.headers.get('sec-fetch-dest') || '';
  return accept.includes('text/html') || dest === 'document';
}

function blockResponse(status, code, message, isBrowser, blockedPath, requestUrl, extraHeaders) {
  if (isBrowser && blockedPath) {
    const url = new URL(blockedPath, requestUrl);
    url.searchParams.set('code', code);
    url.searchParams.set('reason', message);
    url.searchParams.set('status', String(status));
    return new Response(null, {
      status: 302,
      headers: { Location: url.toString(), ...(extraHeaders || {}) },
    });
  }
  return new Response(
    JSON.stringify({ error: message, code, timestamp: new Date().toISOString() }),
    {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        ...(extraHeaders || {}),
      },
    }
  );
}

const DEFAULT_MIDDLEWARE_OPTIONS = {
  guard: {},
  publicPaths: ['/login', '/register', '/blocked', '/403', '/error', '/api/health'],
  authCookie: 'auth_token',
  loginPath: '/login',
  blockedPath: '/blocked',
  apiPrefix: '/api',
  authApiPaths: ['/api/auth'],
  heavyApiPaths: [],
  skipAuth: false,
  skipFirewall: false,
  skipRateLimit: false,
  ipHeaders: ['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for'],
  securityHeaders: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-XSS-Protection': '1; mode=block',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  },
  rateLimit: {
    page:  { max: 300, windowMs: 60000 },
    api:   { max: 200, windowMs: 60000 },
    auth:  { max: 20,  windowMs: 60000 },
    heavy: { max: 60,  windowMs: 60000 },
  },
  bruteForce: {
    enabled: true,
    maxFails: 5,
    lockoutMs: 15 * 60 * 1000,
    paths: ['/login', '/verify-otp', '/verify'],
  },
  maxBodySize: {
    page:  1  * 1024 * 1024,
    api:   5  * 1024 * 1024,
    heavy: 20 * 1024 * 1024,
  },
  onBlock: null,
  onAllow: null,
};

function deepMergeOptions(defaults, overrides) {
  const result = { ...defaults };
  for (const key of Object.keys(overrides || {})) {
    if (
      overrides[key] !== null &&
      typeof overrides[key] === 'object' &&
      !Array.isArray(overrides[key]) &&
      typeof defaults[key] === 'object'
    ) {
      result[key] = deepMergeOptions(defaults[key], overrides[key]);
    } else {
      result[key] = overrides[key];
    }
  }
  return result;
}

function addSecHeaders(response, headers) {
  for (const [k, v] of Object.entries(headers)) {
    if (v) response.headers.set(k, v);
  }
  return response;
}

function createMiddleware(userOptions) {
  const opts = deepMergeOptions(DEFAULT_MIDDLEWARE_OPTIONS, userOptions || {});
  const guard = opts.skipFirewall ? null : createNextGuard(opts.guard);

  return async function nextguardMiddleware(request) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method.toUpperCase();
    const ip = getIp(request, opts.ipHeaders);
    const isBrowser = isBrowserRequest(request, opts.apiPrefix);
    const isApiPath = pathname.startsWith(opts.apiPrefix);
    const isPublic = opts.publicPaths.some(p => pathname === p || pathname.startsWith(p + '/') || pathname.startsWith(p + '?'));
    const isHeavyApi = opts.heavyApiPaths.some(p => pathname === p || pathname.startsWith(p));
    const isAuthApi = opts.authApiPaths.some(p => pathname === p || pathname.startsWith(p));

    const tier = isHeavyApi ? 'heavy' : isAuthApi ? 'auth' : isApiPath ? 'api' : 'page';

    if (!opts.skipFirewall && guard) {
      try {
        const guardResponse = await guard.nextMiddleware(request);
        if (guardResponse) {
          let errorData = {};
          try { errorData = await guardResponse.clone().json(); } catch {}
          const layer = Number(errorData.layer || 0);
          const reason = String(errorData.reason || errorData.error || 'NextGuard Shield');
          const isRateLimit = guardResponse.status === 429 || layer === 2;
          const isBot = layer === 3 || layer === 4;
          const code = isRateLimit ? 'RATE_LIMITED' : isBot ? 'BOT_DETECTED' : `SHIELD_BLOCKED_L${layer}`;
          const msg = isRateLimit ? 'Too many requests' : isBot ? 'Bot/scanner access denied' : `Blocked by firewall (layer ${layer})`;

          if (typeof opts.onBlock === 'function') {
            const custom = await opts.onBlock({ request, ip, code, reason, layer, status: guardResponse.status });
            if (custom instanceof Response) return custom;
          }

          return blockResponse(
            guardResponse.status || 403,
            code,
            msg,
            isBrowser,
            opts.blockedPath,
            request.url,
            {
              'X-NextGuard-Layer': String(layer),
              'Retry-After': isRateLimit ? '60' : '300',
            }
          );
        }
      } catch {}
    }

    if (!opts.skipRateLimit) {
      const rl = checkRateLimit(ip, tier, opts.rateLimit);
      if (!rl.allowed) {
        const msg = `Too many requests. Retry after ${Math.ceil((rl.resetMs - Date.now()) / 1000)}s`;
        if (typeof opts.onBlock === 'function') {
          const custom = await opts.onBlock({ request, ip, code: 'RATE_LIMITED', reason: msg, layer: 'rl', status: 429 });
          if (custom instanceof Response) return custom;
        }
        return blockResponse(429, 'RATE_LIMITED', msg, isBrowser, opts.blockedPath, request.url, {
          'Retry-After': String(Math.ceil((rl.resetMs - Date.now()) / 1000)),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(rl.resetMs),
        });
      }
    }

    if (opts.bruteForce.enabled && isAuthApi) {
      const isBruteTarget = opts.bruteForce.paths.some(p => pathname.includes(p));
      if (isBruteTarget && method === 'POST') {
        const bf = checkBruteForce(ip, opts.bruteForce);
        if (bf.blocked) {
          return blockResponse(429, 'BRUTEFORCE_LOCKOUT', `Too many attempts. Retry in ${bf.remainingSec}s.`, isBrowser, opts.blockedPath, request.url, {
            'Retry-After': String(bf.remainingSec),
          });
        }
      }
    }

    const contentLength = parseInt(request.headers.get('content-length') || '0', 10);
    if (!isNaN(contentLength) && contentLength > 0) {
      const maxSize = isHeavyApi ? opts.maxBodySize.heavy : isApiPath ? opts.maxBodySize.api : opts.maxBodySize.page;
      if (contentLength > maxSize) {
        return blockResponse(413, 'PAYLOAD_TOO_LARGE', `Request too large (max ${Math.round(maxSize / 1024 / 1024)}MB)`, isBrowser, opts.blockedPath, request.url);
      }
    }

    if (!opts.skipAuth && !isPublic) {
      const token = request.cookies ? request.cookies.get(opts.authCookie)?.value : null;
      if (!token) {
        if (isApiPath) {
          return blockResponse(401, 'UNAUTHORIZED', 'Authentication required.', false, null, request.url);
        }
        const loginUrl = new URL(opts.loginPath, request.url);
        loginUrl.searchParams.set('next', pathname);
        return new Response(null, { status: 302, headers: { Location: loginUrl.toString() } });
      }
    }

    if (typeof opts.onAllow === 'function') {
      const custom = await opts.onAllow({ request, ip, tier });
      if (custom instanceof Response) return custom;
    }

    const response = new Response(null, { status: 200 });

    if (opts.securityHeaders) {
      addSecHeaders(response, opts.securityHeaders);
    }

    return null;
  };
}

module.exports = { createMiddleware };
