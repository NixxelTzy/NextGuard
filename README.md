# 🛡️ NextGuard

**7-Layer DDoS Firewall & Active Defense Shield for Node.js + Next.js**

[![npm version](https://img.shields.io/npm/v/nextguard.svg)](https://npmjs.com/package/nextguard)
[![license](https://img.shields.io/npm/l/nextguard.svg)](LICENSE)
[![Node.js](https://img.shields.io/node/v/nextguard.svg)](https://nodejs.org)

NextGuard is a zero-dependency, production-ready firewall middleware that protects your Node.js and Next.js applications from **DDoS attacks**, web exploits, and automated threats — with a built-in **Active Counter-Strike engine** that retaliates against attackers by tarpitting, slow-reading, and reset-storming their connections.

---

## 📦 Installation

```bash
npm install nextguard
```

---

## ⚡ Quick Start

### Express / Node.js

```js
const express = require('express');
const { createNextGuard } = require('nextguard');

const app = express();
const guard = createNextGuard({
  logLevel: 'info',
  layer2: { maxRequests: 60 },
});

app.use(guard.middleware);

app.get('/', (req, res) => res.send('Protected!'));
app.listen(3000, () => console.log('Server running on port 3000'));
```

### Next.js (App Router — `middleware.ts`)

```ts
import { createNextGuard } from 'nextguard';

const guard = createNextGuard({
  logLevel: 'warn',
  layer2: { maxRequests: 100 },
  layer6: { enabled: true, blockedCountries: ['CN', 'RU', 'KP'] },
  layer7: { tarpitEnabled: true, tarpitDelayMs: 15_000 },
});

export const middleware = guard.nextMiddleware;

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

### Raw `http.createServer`

```js
const http = require('http');
const { createNextGuard } = require('nextguard');

const guard = createNextGuard();
const server = http.createServer(guard.handler((req, res) => {
  res.end('Hello, secure world!');
}));
server.listen(3000);
```

---

## 🏰 The 7 Layers

| Layer | Name | What It Does |
|-------|------|-------------|
| **1** | IP Reputation Gate | Static blacklist, CIDR ranges, auto-ban on violations |
| **2** | Rate Limiter | Per-IP request windows, burst detection, cooldown penalties |
| **3** | Behavioral Anomaly | Path-scan detection, JS proof-of-work challenge |
| **4** | Header Integrity | Malicious UA blocking, invalid methods, oversized headers |
| **5** | Payload Inspection | SQLi, XSS, RCE, LFI/Path Traversal detection in query/body/cookies |
| **6** | Geo-Fencing | Country allowlist/blocklist using any IP geo API |
| **7** | Active Counter-Strike | Tarpit, slow-read, reset storm, honeypot traps |

---

## ⚙️ Full Configuration

```js
const guard = createNextGuard({
  // General
  name: 'NextGuard',
  mode: 'protect',      // 'protect' | 'monitor' | 'lockdown'
  trustProxy: true,
  logLevel: 'warn',     // 'silent' | 'warn' | 'info' | 'debug'

  // Layer 1 — IP Reputation
  layer1: {
    enabled: true,
    staticBlacklist: ['192.168.1.100', '10.0.0.0/8'],
    autobanOnViolations: 5,
    banDurationMs: 3_600_000,   // 1 hour
  },

  // Layer 2 — Rate Limiting
  layer2: {
    enabled: true,
    windowMs: 60_000,           // 1-minute window
    maxRequests: 120,           // max requests per IP per window
    burstLimit: 30,             // max per 5-second burst
    burstWindowMs: 5_000,
    penaltyMs: 30_000,          // cooldown after limit exceeded
  },

  // Layer 3 — Behavioral Analysis
  layer3: {
    enabled: true,
    maxPathsPerWindow: 40,      // unique URL paths per window
    maxErrorsPerWindow: 15,     // 4xx errors before flagging
    jsChallenge: false,         // JS proof-of-work for bots
  },

  // Layer 4 — Header Integrity
  layer4: {
    enabled: true,
    requireUserAgent: true,
    blockMaliciousUA: true,
    maxHeaderSize: 8192,
  },

  // Layer 5 — Payload Inspection
  layer5: {
    enabled: true,
    maxBodySize: 2_097_152,     // 2 MB
    inspectQuery: true,
    inspectBody: true,
    inspectCookies: true,
    inspectHeaders: true,
  },

  // Layer 6 — Geo-Fencing
  layer6: {
    enabled: true,
    blockedCountries: ['KP'],
    allowedCountries: [],       // empty = allow all non-blocked
    geoApiUrl: 'http://ip-api.com/json/{ip}?fields=countryCode',
  },

  // Layer 7 — Active Counter-Strike
  layer7: {
    enabled: true,
    tarpitEnabled: true,
    tarpitDelayMs: 10_000,      // freeze attacker for 10s
    tarpitMaxMs: 60_000,        // max tarpit per session
    slowReadEnabled: true,
    slowReadChunkMs: 2_000,
    resetStormEnabled: true,
    honeypotPaths: [
      '/.env', '/wp-admin', '/admin', '/phpmyadmin', '/config.php',
      '/.git/HEAD', '/backup.sql', '/db.sql',
    ],
  },
});
```

---

## 🎮 Runtime API

```js
// Ban an IP manually
guard.ban('1.2.3.4', { durationMs: 3_600_000, reason: 'manual' });

// Unban an IP
guard.unban('1.2.3.4');

// Get real-time stats
const stats = guard.getStats();
console.log(stats);
// {
//   version: '1.0.0',
//   uptime: 1234,
//   mode: 'protect',
//   trackedIPs: 42,
//   bannedIPs: 3,
//   tarpittedIPs: 1,
//   topOffenders: [...]
// }

// Switch to emergency lockdown (blocks ALL traffic)
guard.setMode('lockdown');

// Back to normal
guard.setMode('protect');

// Add to blacklist at runtime
guard.addToBlacklist('203.0.113.0/24');

// Listen to threat events
guard.events.on('threat', ({ ip, layer, reason }) => {
  console.log(`[THREAT] Layer ${layer} | ${ip} | ${reason}`);
  // → send to your logging/alerting system
});
```

---

## 🔗 Admin API Endpoints

NextGuard automatically exposes these internal routes (no extra setup needed):

| Endpoint | Method | Description |
|---------|--------|-------------|
| `/__nextguard/stats` | GET | Real-time statistics |
| `/__nextguard/ban` | POST | Ban an IP `{ ip, durationMs?, reason? }` |
| `/__nextguard/unban` | POST | Unban an IP `{ ip }` |

> **Security note:** Protect these routes with your own authentication middleware in production.

---

## 🧱 Layer 7 — Active Counter-Strike Details

When NextGuard detects an attacker, Layer 7 retaliates with three weapons:

### 🪤 Tarpit
Holds the attacker's TCP connection open by sending a response byte-by-byte. The attacker's threads and file descriptors get tied up, exhausting their attack capacity.

```
Attacker → connects → NextGuard sends 1 byte every 2s → attacker stuck for 10–60s
```

### 🐢 Slow Read
Drains attacker buffers by consuming data painfully slowly, causing memory pressure on their side.

### 💥 Reset Storm
For lower-violation IPs, NextGuard sends a flood of empty writes to confuse port scanners and break their state machines.

### 🍯 Honeypot
Any access to paths like `/.env`, `/wp-admin`, `/phpmyadmin`, `/.git/HEAD`, etc. immediately triggers a full tarpit and adds 5 violation points — auto-banning the IP shortly after.

---

## 🚫 Attack Signatures Detected (Layer 5)

| Category | Examples |
|----------|---------|
| **SQL Injection** | `UNION SELECT`, `OR 1=1`, `sleep()`, `WAITFOR DELAY`, `xp_cmdshell` |
| **XSS** | `<script>`, `javascript:`, `onerror=`, `document.cookie` |
| **Path Traversal** | `../`, `%2e%2e%2f`, `/etc/passwd`, `/proc/self` |
| **RCE** | Shell metacharacters, backticks, `$()` injection, common shell commands |

---

## 🌍 Geo-Fencing (Layer 6)

Use any IP-to-country API. Example with [ip-api.com](http://ip-api.com) (free, no key needed):

```js
layer6: {
  enabled: true,
  geoApiUrl: 'http://ip-api.com/json/{ip}?fields=countryCode',
  blockedCountries: ['CN', 'RU', 'KP', 'IR'],
}
```

For production, consider a local database like [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) to avoid API rate limits.

---

## 📊 Operating Modes

| Mode | Behavior |
|------|---------|
| `protect` | Full active defense — block, ban, tarpit, counter-strike |
| `monitor` | Passive monitoring only — log threats, allow all traffic |
| `lockdown` | Emergency — block ALL incoming traffic |

---

## 🔐 Security Headers Added Automatically

NextGuard automatically adds these headers to every allowed response:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Content-Security-Policy: default-src 'self'; ...
```

---

## 📈 Production Tips

1. **Multi-instance / cluster deployments**: Replace the in-memory `Map` stores with Redis using your preferred client. The `ipStore`, `banlist`, and `tarpitStore` maps can be swapped out.

2. **Behind a load balancer**: Make sure `trustProxy: true` (default) and your LB correctly sets `X-Forwarded-For`.

3. **Rate limit tuning**: Start with generous limits (`maxRequests: 300`) and tighten based on real traffic patterns from `getStats()`.

4. **Log aggregation**: Use `guard.events.on('threat', ...)` to pipe threats to Datadog, Splunk, ELK, etc.

5. **Geo-fencing at scale**: Use a local GeoIP database instead of an HTTP API.

---

## 📝 License

MIT © NextGuard Team
