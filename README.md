# 🛡️ NextGuard

**7-Layer DDoS Firewall & Active Defense Shield with Real-Time Telegram Alerts**  
*Universal security middleware for Next.js (App Router, Pages Router, Vercel Edge & Serverless) and Node.js (Express, Fastify, HTTP).*

[![npm version](https://img.shields.io/npm/v/@nixxeltzy/nextguard.svg)](https://npmjs.com/package/@nixxeltzy/nextguard)
[![license](https://img.shields.io/npm/l/@nixxeltzy/nextguard.svg)](LICENSE)
[![Node.js](https://img.shields.io/node/v/@nixxeltzy/nextguard.svg)](https://nodejs.org)

NextGuard is a zero-dependency, production-ready security engine that shields your web applications from **DDoS floods, bot scanners, and web exploits** — featuring an **Active Counter-Strike engine** (tarpit, slow-read, reset storm) to exhaust attacker resources, plus **instant Telegram alerts** designed for Vercel deployments.

---

## 🧭 Core Principle: 100% Path-Agnostic

> **NextGuard is a firewall engine, NOT a router.**

You have complete freedom over your application paths. NextGuard does **not** hardcode, require, or hijack any URL.

```text
Next.js / Framework
        ↓
Path Matcher (Defined by YOU)
        ↓
NextGuard Middleware
        ↓
7-Layer Firewall Inspection
        ↓
Allow / Block
        ↓
Your Application Route (/, /login, /dashboard, /admin, /api/users, etc.)
```

Any route you define — whether `/`, `/login`, `/dashboard`, `/admin`, `/api/payment`, `/whatever/:id`, or `/custom-path` — is processed transparently by NextGuard without any special route configurations.

---

## 📦 Installation

```bash
npm install @nixxeltzy/nextguard
```

---

## ⚡ Quick Start

### 1. Next.js (`middleware.ts` / `middleware.js`)

#### Option A: Zero-Config Global Protection (Recommended)

```ts
import { nextguard } from "@nixxeltzy/nextguard";

export const middleware = nextguard();

// Protect all routes:
export const config = {
  matcher: ["/:path*"]
};
```

#### Option B: Direct Functional Middleware

```ts
import { nextguard } from "@nixxeltzy/nextguard";

export function middleware(request: Request) {
  return nextguard(request);
}

export const config = {
  matcher: [
    "/api/:path*",
    "/dashboard/:path*",
    "/admin/:path*"
  ]
};
```

#### Option C: With Custom Defense & Telegram Alerts

```ts
import { nextguard } from "@nixxeltzy/nextguard";

export const middleware = nextguard({
  layer2: { maxRequests: 80, windowMs: 60_000 },
  telegram: {
    enabled: true,
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  },
});

export const config = {
  matcher: ["/:path*"]
};
```

---

### 2. Express / Node.js

```js
const express = require('express');
const { nextguard } = require('@nixxeltzy/nextguard');

const app = express();
app.use(express.json());

// Attach firewall
app.use(nextguard({
  telegram: {
    enabled: true,
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
  }
}));

// Define your own routes freely
app.get('/', (req, res) => res.send('Welcome!'));
app.get('/login', (req, res) => res.send('Login'));
app.get('/admin', (req, res) => res.send('Admin Dashboard'));
app.get('/api/users', (req, res) => res.json({ users: [] }));

app.listen(3000, () => console.log('Protected server running on port 3000'));
```

---

## 📱 Telegram Real-Time Security Alerts (Vercel Ready)

NextGuard comes with built-in Telegram alerts that work seamlessly on **Vercel Edge, Vercel Serverless, and Node.js**.

### How to set up in 2 minutes:

1. Create a bot with [@BotFather](https://t.me/BotFather) on Telegram and get your **Bot Token**.
2. Get your **Chat ID** (or Channel/Group ID) from [@userinfobot](https://t.me/userinfobot).
3. In your **Vercel Project Dashboard** (or `.env.local`), add these Environment Variables:

```env
TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
TELEGRAM_CHAT_ID=-1001234567890
```

NextGuard **automatically detects** these environment variables! When an attack is detected, you will immediately receive:

```html
🛡️ [NextGuard] Security Alert
🧱 Layer: Layer 5 (Payload Inspection)
⚠️ Threat: Malicious payload in query string
🌐 Target Path: /api/payment
📍 Attacker IP: 198.51.100.42
📱 Method: GET
⚡ Action: BLOCKED (400 BAD REQUEST)
⏰ Timestamp: 2026-10-05T14:25:00.000Z
```

### 🛡️ Built-in DDoS Anti-Spam (Throttle)
During high-volume DDoS attacks (e.g. 5,000 req/sec), NextGuard automatically throttles Telegram alerts with an intelligent debounce cooldown (default: 30 seconds per IP/layer). Your Telegram inbox will never get flooded or rate-limited!

---

## 🏰 The 7 Defense Layers

| Layer | Name | Description |
|-------|------|-------------|
| **1** | **IP Reputation Gate** | Static CIDR blacklist, auto-ban after repeated violations, fast in-memory lookup. |
| **2** | **Rate Limiter & Burst DDoS** | Per-IP sliding window throttle + micro-burst detector for layer-7 HTTP flood mitigation. |
| **3** | **Behavioral Anomaly** | Detects crawler/fuzzer path-scanning behaviors. Optional client-side JS Proof-of-Work challenge. |
| **4** | **Header & Protocol Integrity** | Blocks 50+ scanner tools (sqlmap, nikto, masscan, nuclei, dirbuster, etc.), verifies HTTP methods and header size limits. |
| **5** | **Payload Deep Inspection** | Inspects query parameters, cookies, request headers, and JSON body for SQLi, XSS, RCE, and Path Traversal (`../etc/passwd`). |
| **6** | **Geo-Fencing** | Block or allow traffic based on ISO country codes using any IP-Geo API or database. |
| **7** | **Active Counter-Strike** | Retaliates against detected attackers: **Tarpit** (freezes TCP socket up to 60s), **Slow-Read** (drains attacker buffers), **Reset Storm** (scrambles scanner state machines), and pure exploit lure **Honeypots**. |

---

## ⚔️ Active Counter-Strike Weapons (Layer 7)

Unlike passive firewalls that simply return `403 Forbidden` and let the attacker immediately retry, NextGuard fights back:

1. **TCP Tarpit:** Holds the attacker's connection open by trickling response bytes slowly. This exhausts the attacker's client threads, socket handles, and connection pools.
2. **Slow-Read Drainage:** Reads attacker payload painfully slowly, forcing memory pressure back onto the attacker's machine.
3. **Reset Storm:** Sends rapid empty writes to disrupt automated port scanners and exploit frameworks.
4. **Clean Honeypots:** Triggers on genuine exploit probes (`/.env`, `/.git/HEAD`, `/wp-config.php`, `/phpmyadmin`). Real application routes like `/admin` or `/dashboard` are **never** blocked!

---

## ⚙️ Full Configuration Reference

```ts
import { nextguard } from "@nixxeltzy/nextguard";

export const middleware = nextguard({
  // General
  mode: 'protect',            // 'protect' (active defense) | 'monitor' (log only) | 'lockdown' (block all)
  trustProxy: true,           // Respect X-Forwarded-For & CF-Connecting-IP
  logLevel: 'warn',           // 'silent' | 'warn' | 'info' | 'debug'

  // Telegram Notifications
  telegram: {
    enabled: true,
    botToken: process.env.TELEGRAM_BOT_TOKEN,
    chatId: process.env.TELEGRAM_CHAT_ID,
    cooldownMs: 30_000,       // Cooldown between alerts per IP+Layer to avoid DDoS spam
    minLayer: 1,              // Minimum layer to trigger alerts (1-7)
  },

  // Layer 1 — IP Reputation
  layer1: {
    enabled: true,
    staticBlacklist: ['198.51.100.0/24'],
    autobanOnViolations: 5,   // Auto-ban after 5 violations
    banDurationMs: 3_600_000, // Ban for 1 hour
  },

  // Layer 2 — Rate Limiting
  layer2: {
    enabled: true,
    windowMs: 60_000,         // 1 minute window
    maxRequests: 120,         // Max 120 requests per window
    burstLimit: 30,           // Max 30 requests per 5s burst
    burstWindowMs: 5_000,
    penaltyMs: 30_000,
  },

  // Layer 3 — Behavioral
  layer3: {
    enabled: true,
    maxPathsPerWindow: 40,    // Unique paths visited before flagged as scanner
    jsChallenge: false,       // Set true for JS Proof-of-Work challenge
  },

  // Layer 4 — Headers
  layer4: {
    enabled: true,
    requireUserAgent: true,
    blockMaliciousUA: true,   // Block sqlmap, nmap, nikto, curl/7.x, etc.
  },

  // Layer 5 — Payload Inspection
  layer5: {
    enabled: true,
    inspectQuery: true,
    inspectBody: true,
    inspectCookies: true,
    inspectHeaders: true,
  },

  // Layer 6 — Geo-Fencing
  layer6: {
    enabled: false,
    blockedCountries: ['KP'], // ISO-3166 alpha-2
    allowedCountries: [],     // If non-empty, only allow these
    geoApiUrl: 'http://ip-api.com/json/{ip}?fields=countryCode',
  },

  // Layer 7 — Active Counter-Strike
  layer7: {
    enabled: true,
    tarpitEnabled: true,
    tarpitDelayMs: 10_000,    // Freeze attacker for 10 seconds
    tarpitMaxMs: 60_000,
    slowReadEnabled: true,
    resetStormEnabled: true,
    honeypotPaths: ['/.env', '/.git/HEAD', '/wp-config.php', '/phpmyadmin'],
  },
});
```

---

## 🎮 Runtime API

```js
import { nextguard } from "@nixxeltzy/nextguard";

const guard = nextguard();

// Manually ban an IP
guard.ban('198.51.100.5', { durationMs: 3600000, reason: 'Manual ban' });

// Unban an IP
guard.unban('198.51.100.5');

// Emergency lockdown: block ALL traffic instantly
guard.setMode('lockdown');

// Back to normal protection
guard.setMode('protect');

// Real-time security statistics
console.log(guard.getStats());

// Listen for threat events in your code
guard.events.on('threat', ({ ip, layer, reason, path }) => {
  console.log(`[ALERT] Layer ${layer} blocked ${ip} on ${path}: ${reason}`);
});
```

---

## 📝 License

MIT © [NixxelTzy](https://github.com/NixxelTzy/nextguard)
