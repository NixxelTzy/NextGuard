# 🛡️ NextGuard

**Production-ready Web Application Firewall (WAF) untuk Next.js dan Node.js**

Proteksi komprehensif terhadap ancaman web paling umum — **DDoS, DoS, SQL Injection, XSS, Command Injection, Path Traversal, dan Malicious Bots** — dalam satu package yang mudah diinstall.

---

## ✨ Fitur Utama

| Fitur | Deskripsi |
|---|---|
| 🚦 **Rate Limiting & Anti-DoS** | Sliding window counter dengan auto IP Jail (mirip Fail2ban) |
| 💉 **SQL Injection Detection** | Pattern matching multi-layer: tautology, UNION, time-based blind, schema extraction |
| ⚡ **XSS Protection** | Deteksi script tags, event handler inline, javascript: URI, HTML entity bypass |
| 🖥️ **Command Injection** | Deteksi shell chaining, reverse shell, substitusi command |
| 📂 **Path Traversal / LFI** | Deteksi `../`, null-byte, PHP wrappers, file sensitif sistem |
| 🤖 **Bad Bot / Scanner Detection** | Blokir sqlmap, nikto, acunetix, dirbuster, nuclei, wfuzz, dll |
| 🌐 **IP Filtering + CIDR** | Whitelist/Blacklist dengan dukungan subnet notation (e.g. `10.0.0.0/8`) |
| 📦 **Payload Guard** | Proteksi dari oversized payload yang bisa menyebabkan DoS |
| 🔒 **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, dan lainnya |
| 🛠️ **Custom Rules** | Buat aturan keamanan sendiri dengan fungsi sync/async |
| 🔴 **Monitor Mode** | Log ancaman tanpa memblokir — cocok untuk testing dan staging |
| 🗂️ **Per-Endpoint Config** | Override konfigurasi firewall per route/endpoint |
| 🔄 **Redis Store** | Distributed rate limiting untuk multi-instance / serverless |

---

## 📦 Instalasi

```bash
npm install nextguard
# atau
yarn add nextguard
# atau
pnpm add nextguard
```

---

## 🚀 Quick Start

### 1. Next.js — Global Middleware (`middleware.ts`)

Tempatkan file ini di root proyek Next.js kamu:

```ts
// middleware.ts
import { createNextGuardMiddleware } from 'nextguard';

export const middleware = createNextGuardMiddleware({
  rateLimit: {
    windowMs: 60 * 1000, // 1 menit
    max: 100,            // max 100 request per menit per IP
  },
  sqlInjection: { enabled: true },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { blockEmptyUserAgent: true },
  onBlocked: (verdict) => {
    console.warn(`Blocked ${verdict.threatType} from ${verdict.clientIp}`);
  },
});

export const config = {
  // Terapkan ke semua route kecuali assets statis
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

---

### 2. Next.js — App Router per Route (`app/api/.../route.ts`)

```ts
// app/api/login/route.ts
import { withNextGuard } from 'nextguard';

async function handler(req: Request): Promise<Response> {
  const body = await req.json();
  // ... logic login kamu
  return Response.json({ token: 'xxx' });
}

// Proteksi endpoint login dengan rate limit ketat
export const POST = withNextGuard(handler, {
  rateLimit: {
    windowMs: 60 * 1000,
    max: 5,              // Hanya 5 percobaan login per menit
    jailDurationMs: 15 * 60 * 1000, // Banned 15 menit jika flooding
  },
  sqlInjection: { sensitivity: 'high' },
  xss: { enabled: true },
});
```

---

### 3. Next.js — Pages Router (`pages/api/...ts`)

```ts
// pages/api/users/index.ts
import { withNextGuardPages } from 'nextguard';
import type { NextApiRequest, NextApiResponse } from 'next';

async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({ users: [] });
}

export default withNextGuardPages(handler, {
  rateLimit: { max: 50, windowMs: 60 * 1000 },
  sqlInjection: { enabled: true },
  xss: { enabled: true },
});
```

---

### 4. Express.js / Node.js

```ts
// server.ts
import express from 'express';
import { nextGuardExpress } from 'nextguard';

const app = express();
app.use(express.json());

// Terapkan firewall secara global
app.use(nextGuardExpress({
  rateLimit: { windowMs: 60 * 1000, max: 100 },
  sqlInjection: { enabled: true },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { knownScanners: true },
  securityHeaders: { enabled: true },
}));

app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000);
```

---

## ⚙️ Konfigurasi Lengkap

```ts
import { createNextGuardMiddleware } from 'nextguard';

createNextGuardMiddleware({
  // Mode: 'enforce' = blokir ancaman, 'monitor' = hanya log tanpa blokir
  mode: 'enforce',

  // --- Anti-DDoS & Rate Limiting ---
  rateLimit: {
    enabled: true,
    windowMs: 60 * 1000,         // Jendela waktu (ms), default: 1 menit
    max: 100,                    // Maks request per jendela waktu
    jailThreshold: 200,          // Auto-jail jika melewati threshold ini
    jailDurationMs: 5 * 60 * 1000, // Durasi ban (ms), default: 5 menit
    headers: true,               // Kirim X-RateLimit-* headers
    keyGenerator: (req) => req.ip, // Fungsi kustom untuk membuat key
  },

  // --- SQL Injection Protection ---
  sqlInjection: {
    enabled: true,
    sensitivity: 'medium', // 'low' | 'medium' | 'high'
    inspectQuery: true,    // Inspect query params
    inspectBody: true,     // Inspect request body
    inspectHeaders: false, // Inspect request headers
    customPatterns: [/my_custom_sqli_regex/i], // Tambah pattern sendiri
    excludePatterns: [/safe_pattern/],         // Kecualikan pattern tertentu
  },

  // --- XSS Protection ---
  xss: {
    enabled: true,
    sensitivity: 'medium',
    inspectQuery: true,
    inspectBody: true,
    customPatterns: [],
  },

  // --- Command Injection Protection ---
  commandInjection: {
    enabled: true,
    inspectQuery: true,
    inspectBody: true,
    customPatterns: [],
  },

  // --- Path Traversal & LFI/RFI Protection ---
  pathTraversal: {
    enabled: true,
    inspectUrl: true,
    inspectQuery: true,
    inspectBody: true,
    customPatterns: [],
  },

  // --- Bot & Scanner Detection ---
  badBots: {
    enabled: true,
    blockEmptyUserAgent: false, // Blokir request tanpa User-Agent
    knownScanners: true,        // Blokir sqlmap, nikto, acunetix, dll
    customBlacklist: ['BadBot/1.0', /evilcrawler/i],
    whitelist: [/googlebot/i, /bingbot/i], // Whitelist bot yang diizinkan
  },

  // --- IP Filtering (Supports CIDR) ---
  ipFilter: {
    whitelist: ['127.0.0.1', '10.0.0.0/8', '192.168.1.0/24'],
    blacklist: ['198.51.100.0/24'],
    trustProxy: true,                  // Percaya X-Forwarded-For header
    customIpHeader: 'cf-connecting-ip', // Header kustom untuk IP (Cloudflare, dll)
  },

  // --- Payload Size Guard ---
  payloadGuard: {
    enabled: true,
    maxBodySize: 10 * 1024 * 1024, // 10MB default
  },

  // --- Security Response Headers ---
  securityHeaders: {
    enabled: true,
    xFrameOptions: 'DENY',
    xContentTypeOptions: true,
    strictTransportSecurity: 'max-age=31536000; includeSubDomains; preload',
    referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: 'camera=(), microphone=(), geolocation=()',
    contentSecurityPolicy: "default-src 'self'",
  },

  // --- Per-Endpoint Rule Overrides ---
  endpoints: {
    '/api/login': {
      rateLimit: { max: 5, windowMs: 60 * 1000, jailDurationMs: 15 * 60 * 1000 },
    },
    '/api/upload': {
      payloadGuard: { maxBodySize: 50 * 1024 * 1024 }, // 50MB untuk upload
    },
    '/api/public': {
      rateLimit: { max: 500 }, // Rate limit lebih longgar
      xss: false,              // Matikan XSS check untuk endpoint ini
    },
  },

  // --- Exclude Paths (Tidak di-check firewall) ---
  excludePaths: [
    '/_next/*',
    '/favicon.ico',
    '/robots.txt',
    /^\/public\/.*/,
  ],

  // --- Custom Rules ---
  customRules: [
    {
      name: 'require_auth',
      description: 'Wajib ada Authorization header untuk /api/private/*',
      evaluate: async (req) => {
        if (!req.url.startsWith('/api/private/')) return false;
        return !req.headers['authorization'];
      },
      action: 'block',
      statusCode: 401,
      reason: 'Authorization required',
    },
  ],

  // --- Callback Hooks ---
  onBlocked: (verdict, req) => {
    console.error(`[SECURITY] ${verdict.threatType} blocked from ${verdict.clientIp}: ${verdict.reason}`);
    // Bisa: kirim alert, simpan ke DB, kirim ke SIEM, dll
  },

  onAllowed: (verdict, req) => {
    // Dipanggil untuk setiap request yang diizinkan (gunakan dengan hati-hati — dapat verbose)
  },

  // Tampilkan HTML block page untuk browser request (mirip Cloudflare)
  htmlResponse: true,
});
```

---

## 🔴 Monitor Mode

Gunakan `mode: 'monitor'` untuk **mendeteksi ancaman tanpa memblokir**. Berguna saat testing atau pertama kali deploy.

```ts
createNextGuardMiddleware({
  mode: 'monitor', // Hanya log, tidak blokir!
  onBlocked: (verdict) => {
    console.warn(`[MONITOR] Would have blocked: ${verdict.threatType} from ${verdict.clientIp}`);
    // Kirim ke logging service: DataDog, Sentry, LogFlare, dll
  },
});
```

---

## 🔄 Redis Store (Multi-Instance / Serverless)

Untuk aplikasi dengan banyak instance atau serverless, gunakan `RedisStore` agar rate limit tersinkronisasi:

```ts
import { nextGuardExpress, RedisStore } from 'nextguard';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

app.use(nextGuardExpress({
  rateLimit: {
    max: 100,
    windowMs: 60 * 1000,
    store: new RedisStore({
      client: redis,
      prefix: 'myapp:waf:', // Optional prefix untuk Redis keys
    }),
  },
}));
```

**Redis clients yang didukung:** `ioredis`, `node-redis`, `@upstash/redis`, Dragonfly, KeyDB, Valkey.

---

## 🛠️ Custom Rules

```ts
customRules: [
  {
    name: 'block_suspicious_ips',
    evaluate: (req) => {
      const blockedRanges = ['45.142.212.'];
      return blockedRanges.some(prefix => req.ip.startsWith(prefix));
    },
    action: 'block',
    statusCode: 403,
    reason: 'IP dari range yang tidak diizinkan',
  },

  // Async rule — cek reputasi IP ke external service
  {
    name: 'threat_intel_check',
    evaluate: async (req) => {
      // const reputation = await checkIPReputation(req.ip);
      // return reputation.score < 50;
      return false; // placeholder
    },
    action: 'block',
  },
]
```

---

## 📋 Response Format

### JSON Response (API Request)
```json
{
  "success": false,
  "error": "Access Denied by NextGuard Firewall",
  "code": "FIREWALL_BLOCKED",
  "threat": "sql_injection",
  "reason": "SQL Injection detected in parameter: query.search",
  "clientIp": "192.168.1.100",
  "requestId": "ng_abc123_xyz456",
  "timestamp": "2026-10-03T12:34:56.000Z"
}
```

### HTML Response (Browser Request)
Saat `htmlResponse: true`, browser akan mendapatkan halaman blokir yang elegan (mirip Cloudflare) dengan detail ancaman dan Request ID.

---

## 🔐 Ancaman yang Dilindungi

| Ancaman | Method Deteksi |
|---|---|
| SQL Injection | Tautology, UNION, stacked queries, time-based blind, schema extraction |
| XSS | Script tags, event handlers, javascript: URI, HTML entities encoding bypass |
| OS Command Injection | Shell chaining (`;`, `&&`, `\|`), substitution (`$(...)`), reverse shells |
| Path Traversal / LFI | `../`, null-byte, URL encoding bypass, PHP wrappers (php://, data://) |
| DDoS / DoS | Sliding window rate limit, auto IP jailing (Fail2ban style) |
| Malicious Bots | sqlmap, nikto, acunetix, dirbuster, gobuster, nuclei, wfuzz, dan lainnya |
| Oversized Payload | Content-Length limit enforcement |
| IP Blacklist | Exact match dan CIDR subnet matching |

---

## 📁 Struktur Package

```
nextguard/
├── src/
│   ├── core/
│   │   ├── detectors/
│   │   │   ├── sqli.ts          # SQL Injection detector
│   │   │   ├── xss.ts           # XSS detector
│   │   │   ├── command-injection.ts
│   │   │   ├── path-traversal.ts
│   │   │   └── bot.ts           # Bot & Scanner detector
│   │   ├── stores/
│   │   │   ├── memory-store.ts  # In-memory store (default)
│   │   │   └── redis-store.ts   # Redis distributed store
│   │   ├── engine.ts            # Core WAF engine
│   │   ├── rate-limiter.ts      # Rate limiting & DoS mitigation
│   │   └── ip-filter.ts         # IP & CIDR filter
│   ├── middleware/
│   │   ├── nextjs.ts            # Next.js adapters
│   │   └── express.ts           # Express/Node.js adapter
│   ├── security/
│   │   └── headers.ts           # Security headers
│   ├── templates/
│   │   └── blocked-page.ts      # HTML block page & JSON response
│   ├── types.ts                 # TypeScript type definitions
│   └── index.ts                 # Main entrypoint & exports
├── tests/                       # 37 unit & integration tests
├── examples/
│   ├── nextjs-example/          # Contoh Next.js (middleware, App Router, Pages Router)
│   ├── express-example/         # Contoh Express.js
│   └── redis-store-example.ts   # Contoh Redis Store
└── dist/                        # Build output (CJS + ESM + TypeScript declarations)
```

---

## 📝 License

MIT © NextGuard Team
