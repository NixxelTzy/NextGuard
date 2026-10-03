# 🛡️ NextGuard

<p align="center">
  <strong>Enterprise-Grade Web Application Firewall (WAF) & Active Defense Shield untuk Node.js dan Next.js</strong><br>
  <em>Perlindungan 7 Lapis, Automatic Endpoint Discovery, Deteksi Multi-Vektor, dan Active Exploit Neutralizer.</em>
</p>

<p align="center">
  <a href="https://github.com/NixxelTzy/NextGuard"><img src="https://img.shields.io/badge/NextGuard-v1.0.0-blue.svg" alt="Version"></a>
  <a href="https://github.com/NixxelTzy/NextGuard/actions"><img src="https://img.shields.io/badge/tests-127%20passed-brightgreen.svg" alt="Tests"></a>
  <a href="https://github.com/NixxelTzy/NextGuard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D18.0.0-orange.svg" alt="Node Version"></a>
</p>

---

## 📑 Daftar Isi

- [✨ Gambaran Umum](#-gambaran-umum)
- [🧱 Arsitektur Firewall 7 Lapis](#-arsitektur-firewall-7-lapis)
- [💥 Fitur Active Exploit Neutralizer (Crash Response)](#-fitur-active-exploit-neutralizer-crash-response)
- [📦 Instalasi](#-instalasi)
- [🚀 Quick Start (Setup 1 Kali Saja)](#-quick-start-setup-1-kali-saja)
  - [1. Node.js / Express (`@nextguard/node`)](#1-nodejs--express-nextguardnode)
  - [2. Next.js (`@nextguard/next`)](#2-nextjs-nextguardnext)
- [🎯 Contoh Proteksi Endpoint Nyata](#-contoh-proteksi-endpoint-nyata)
- [🔍 Automatic Endpoint Discovery & Telemetri](#-automatic-endpoint-discovery--telemetri)
- [📍 Pelacakan Geolocation, Koordinat & Perangkat Penyerang](#-pelacakan-geolocation-koordinat--perangkat-penyerang)
- [🍯 Active Deception (Honeypot Trap) & Reputasi IP (Fail2Ban)](#-active-deception-honeypot-trap--reputasi-ip-fail2ban)
- [🔔 Integrasi Webhook (Discord / Slack)](#-integrasi-webhook-discord--slack)
- [⚙️ Referensi Konfigurasi Lengkap](#️-referensi-konfigurasi-lengkap)
- [🧪 Pengujian & Verifikasi](#-pengujian--verifikasi)

---

## ✨ Gambaran Umum

**NextGuard** dirancang khusus untuk melindungi aplikasi Node.js (Express, Fastify, Connect) dan Next.js (App Router & Pages Router) dari serangan siber modern. Cukup dipasang **SATU KALI** di entry point utama aplikasi, seluruh endpoint Anda otomatis terproteksi tanpa perlu mengimpor firewall di setiap file route.

### 🛡️ Fitur-Fitur Utama

1. **Firewall 7 Lapis (*7-Layer Defense-in-Depth*):** Penyaringan berurutan dari layer jaringan hingga payload aplikasi.
2. **Active Exploit Neutralizer:** Memaksa request serangan menjadi **error fatal** (`ERR_EXPLOIT_PAYLOAD_NEUTRALIZED`) dan langsung memutus koneksi TCP (`Connection: close`), merusak loop automated scanner (Python, cURL, sqlmap) seketika.
3. **Automatic Endpoint Discovery:** Menemukan dan mencatat semua endpoint aktif langsung dari traffic nyata (bukan scan source code, tanpa input daftar manual).
4. **Anti-DDoS & Sliding-Window Rate Limiting:** Pembatasan request cerdas per IP/token dengan auto-jail instan bagi penyerang yang membanjiri server.
5. **Multi-Vector Exploit Engine:**
   - 💉 **SQL Injection (SQLi):** Tautologi (`' OR 1=1`), UNION SELECT, blind time-based, dsb.
   - 🍃 **NoSQL Injection (NoSQLi):** Injeksi operator MongoDB (`$where`, `$gt`, `$ne`, `$regex`, `$in`).
   - ⚡ **Cross-Site Scripting (XSS):** Script tag, event inline handler, `javascript:` URI, dsb.
   - 🖥️ **Command Injection:** Shell piping (`|`, `;`, `&&`), reverse shells, command substitution.
   - 📂 **Path Traversal / LFI:** `../`, null-byte injection (`%00`), PHP wrappers, sistem file sensitif.
   - 🧬 **Prototype Pollution:** Manipulasi objek JavaScript (`__proto__`, `constructor.prototype`).
   - 🌐 **SSRF (Server-Side Request Forgery):** Cloud metadata (`169.254.169.254`), loopback (`127.0.0.1`, `localhost`), IP privat RFC 1918.
6. **Active Deception & Honeypot:** Jalur jebakan (`/.env`, `/.git`, `/wp-admin`, dll.) yang langsung mengkarantina IP penyerang selama 24 jam.
7. **Adaptive IP Reputation (Fail2Ban-Style):** Sistem strike penalti bertingkat (15 menit ➔ 2 jam ➔ 24 jam ➔ 7 hari).
8. **Threat Forensics & Telemetry:** Mengambil lokasi negara, kota, koordinat (lintang/bujur), sistem operasi, jenis perangkat, dan alat yang digunakan dalam serangan.

---

## 🧱 Arsitektur Firewall 7 Lapis

```
[ TRAFFIC MASUK DARI CLIENT / INTERNET ]
                    │
┌───────────────────▼─────────────────────────────────────────────────────┐
│  LAPIS 1: Network & IP Governance                                      │
│  • Whitelist & Blacklist IP instan                                     │
│  • CIDR Subnet range filtering (e.g. 10.0.0.0/8)                       │
└───────────────────┬─────────────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────────────┐
│  LAPIS 2: HTTP Protocol & Request Smuggling Sanitizer                  │
│  • Blokir method terlarang (TRACE, TRACK, CONNECT, DEBUG)               │
│  • Deteksi Request Smuggling (Conflicting Content-Length/Chunked)       │
│  • Sanitasi CRLF injection (HTTP Splitting) & Null-Byte di header      │
│  • Header overflow protection (431 Header Too Large)                    │
└───────────────────┬─────────────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────────────┐
│  LAPIS 3: Volumetric Anti-DDoS & Burst Suppression                    │
│  • Sliding window rate limiter per IP / User token                      │
│  • Burst spike arrest (meredam lonjakan request mendadak)              │
│  • Auto-jail instan bagi penyerang yang membanjiri traffic             │
└───────────────────┬─────────────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────────────┐
│  LAPIS 4: Active Deception & Tripwire Honeypot                          │
│  • Jebakan endpoint pemindai (/.env, /.git, /wp-admin, dll.)           │
│  • Penyerang otomatis terdeteksi & diisolasi 24 jam penuh               │
└───────────────────┬─────────────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────────────┐
│  LAPIS 5: Automated Scanner & Malicious Bot Defense                     │
│  • Signature pemindai kerentanan (sqlmap, nikto, nuclei, acunetix)      │
│  • Deteksi User-Agent kosong, palsu, atau CLI script                    │
└───────────────────┬─────────────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────────────┐
│  LAPIS 6: Deep Content & Multi-Vector Exploit Inspection               │
│  • SQL Injection, NoSQL Injection, XSS, Command Injection              │
│  • Path Traversal, Prototype Pollution, SSRF                           │
└───────────────────┬─────────────────────────────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────────────────────────────┐
│  LAPIS 7: Active Exploit Neutralizer & Crash Terminator 💥              │
│  • Mengubah payload menjadi error sintetis yang merusak script penyerang│
│  • Pemutusan koneksi seketika (Connection: close / TCP Stream Abort)    │
│  • Serangan langsung terhenti dan gagal mengeksekusi                    │
└───────────────────┬─────────────────────────────────────────────────────┘
                    │
      [ REQUEST AMAN DITERUSKAN KE ENDPOINT WEBSITE ASLI ]
```

---

## 💥 Fitur Active Exploit Neutralizer (Crash Response)

Saat penyerang mengirimkan payload eksploitasi, NextGuard **tidak hanya memblokir**, tetapi **secara aktif merusak jalannya script penyerang**:

1. **Pemutusan Koneksi TCP Seketika (`Connection: close` / `destroySocket`):**
   Memicu error jaringan fatal pada script penyerang (`ECONNRESET`, `Connection reset by peer`, `Broken Pipe`).
2. **Respons Error Sintetis (`ERR_EXPLOIT_PAYLOAD_NEUTRALIZED`):**
   Format respons khusus yang menyebabkan parser otomatis penyerang gagal parsing dan crash seketika:
   ```json
   {
     "error": "ERR_EXPLOIT_PAYLOAD_NEUTRALIZED",
     "status": "attack_intercepted",
     "layer": "Layer_7_Exploit_Neutralizer",
     "threat": "command_injection",
     "reason": "Remote OS Command Injection detected in parameter: cmd",
     "code": "E_EXPLOIT_ABORTED",
     "message": "The incoming exploit vector was intercepted and neutralized. Execution terminated immediately.",
     "requestId": "ng_m7k29a_b9x1c2",
     "timestamp": 1728000000000
   }
   ```

---

## 📦 Instalasi

Install core library NextGuard ke proyek Anda:

```bash
npm install nextguard
# atau
yarn add nextguard
# atau
pnpm add nextguard
```

---

## 🚀 Quick Start (Setup 1 Kali Saja)

### 1. Node.js / Express (`@nextguard/node`)

Cukup pasang **SATU KALI** di server utama (`server.js` atau `index.ts`). Semua routes di bawahnya otomatis terlindungi tanpa perlu mengimpor NextGuard di file controller masing-masing:

```ts
import express from 'express';
import { NextGuard } from '@nextguard/node';

const app = express();
app.use(express.json());

// Inisialisasi NextGuard Firewall
const guard = NextGuard({
  apiKey: process.env.NEXTGUARD_KEY,
  // Aktifkan Firewall 7 Lapis & Exploit Neutralizer
  sevenLayerShield: {
    enabled: true,
    neutralizeMode: 'synthetic_error', // atau 'abort_stream'
  },
  // Aktifkan telemetri & monitoring
  telemetry: { enabled: true, maxHistory: 500 },
});

// Pasang middleware SATU KALI di entry point
app.use(guard.middleware());

// ========================================================
// SEMUA ENDPOINT DI BAWAH INI OTOMATIS TERLINDUNGI 100%!
// Anda TIDAK PERLU mengimpor NextGuard di setiap file route.
// ========================================================

app.get('/api/users', (req, res) => res.json({ users: ['Alice', 'Bob'] }));
app.post('/api/upload', (req, res) => res.json({ uploaded: true }));
app.post('/api/payment', (req, res) => res.json({ status: 'paid' }));
app.delete('/api/account', (req, res) => res.json({ deleted: true }));

app.listen(3000, () => console.log('Server berjalan terlindungi di port 3000'));
```

---

### 2. Next.js (`@nextguard/next`)

Di Next.js (baik **App Router** maupun **Pages Router**), cukup pasang satu kali di root file `middleware.ts`:

```ts
// middleware.ts
import { NextGuard } from '@nextguard/next';

export const guard = NextGuard({
  apiKey: process.env.NEXTGUARD_KEY,
  sevenLayerShield: {
    enabled: true,
    neutralizeMode: 'synthetic_error',
  },
  telemetry: { enabled: true },
});

// Export default middleware handler
export default guard.middleware();

export const config = {
  // Tangkap seluruh request dinamis
  matcher: '/:path*',
};
```

Setiap file di `app/api/login/route.ts`, `app/api/upload/route.ts`, atau `pages/api/users.ts` **tidak perlu mengimpor NextGuard**. Next.js Middleware otomatis mencegat dan mensterilkan setiap request sebelum sampai ke handler route.

---

## 🎯 Contoh Proteksi Endpoint Nyata

Berikut adalah contoh skenario bagaimana NextGuard secara otomatis mengamankan berbagai jenis endpoint Anda dari serangan eksploitasi:

### Skenario 1: Endpoint Otentikasi (`POST /api/login`)
* **Serangan:** Penyerang mengirim payload SQL Injection di form username: `' OR 1=1 --`.
* **Aksi NextGuard:** Terdeteksi di Layer 6 (SQLi Detector) dan dinetralisir di Layer 7.
* **Hasil:** Request ditolak dengan kode `400 Bad Request` dan error `ERR_EXPLOIT_PAYLOAD_NEUTRALIZED`. Fungsi otentikasi database Anda tidak pernah tersentuh.

```ts
// app/api/login/route.ts (Next.js) atau controllers/auth.js (Express)
// KODE BERSIH: Tidak ada boiler-plate firewall sama sekali!
export async function POST(req: Request) {
  const { username, password } = await req.json();
  // Hanya request yang 100% steril yang akan sampai ke sini
  const user = await db.findUser(username, password);
  return Response.json({ user });
}
```

### Skenario 2: Endpoint Upload File (`POST /api/upload`)
* **Serangan:** Penyerang mencoba Path Traversal untuk menulis file ke direktori sistem: `../../../../etc/shadow`.
* **Aksi NextGuard:** Terdeteksi di Layer 6 (Path Traversal / LFI Detector).
* **Hasil:** Request dibatalkan seketika sebelum file apapun tersimpan di server.

### Skenario 3: Endpoint Transaksi & Pembayaran (`POST /api/payment`)
* **Serangan:** Penyerang membanjiri ribuan transaksi palsu (DDoS/Spam) atau mencoba manipulasi NoSQL: `{"amount": {"$gt": 0}}`.
* **Aksi NextGuard:** Meredam lonjakan request di Layer 3 (Anti-DDoS Sliding Window) dan memblokir operator NoSQL di Layer 6.

### Skenario 4: Optional Per-Endpoint Protection (Aturan Khusus)
Jika Anda ingin aturan yang jauh lebih ketat khusus pada endpoint tertentu (misal: proteksi brute-force login maksimal 5 request per menit):

```ts
// Opsional: override aturan untuk endpoint sensitif
guard.protect('/api/login', {
  rateLimit: {
    max: 5,               // Maksimal 5 percobaan
    windowMs: 60 * 1000,  // per 1 menit
    jailDurationMs: 15 * 60 * 1000, // Ban 15 menit jika melebihi batas
  },
  sqlInjection: { sensitivity: 'high' },
});
```

---

## 🔍 Automatic Endpoint Discovery & Telemetri

NextGuard otomatis mendeteksi endpoint dari **request aktual** yang masuk. Anda tidak perlu mendaftarkan endpoint secara manual.

Untuk melihat daftar endpoint yang ditemukan beserta statistik trafiknya:

```ts
// Ambil seluruh endpoint yang ditemukan dari trafik nyata
const endpoints = guard.getDiscoveredEndpoints();
console.log(endpoints);

/* Output:
[
  {
    id: "GET:/api/users",
    method: "GET",
    path: "/api/users",
    requestCount: 142,
    allowedCount: 142,
    blockedCount: 0,
    lastStatusCode: 200,
    firstSeen: 1728001000000,
    lastSeen: 1728003400000
  },
  {
    id: "POST:/api/login",
    method: "POST",
    path: "/api/login",
    requestCount: 35,
    allowedCount: 32,
    blockedCount: 3, // 3 serangan dicegat!
    lastStatusCode: 400
  }
]
*/

// Ambil ringkasan statistik
const stats = guard.getStats();
console.log(stats);
// { totalEndpoints: 5, totalRequests: 540, totalBlocked: 12, totalAllowed: 528 }
```

---

## 📍 Pelacakan Geolocation, Koordinat & Perangkat Penyerang

NextGuard dilengkapi modul forensik cerdas yang melacak identitas fisik penyerang secara defensif:

```ts
// Ambil 50 log serangan terakhir
const threatLogs = guard.getThreatLogs(50);

threatLogs.forEach(attack => {
  console.log(`[ATTACK INTERCEPTED]`);
  console.log(`IP Penyerang : ${attack.clientIp}`);
  console.log(`Negara & Kota: ${attack.geo.city}, ${attack.geo.countryCode}`);
  console.log(`Koordinat    : Lintang ${attack.geo.coordinates?.latitude}, Bujur ${attack.geo.coordinates?.longitude}`);
  console.log(`Perangkat    : ${attack.client.deviceType} (${attack.client.os})`);
  console.log(`Browser/Tool : ${attack.client.browser}`); // e.g. "sqlmap (Exploit Scanner)"
  console.log(`Jenis Serangan: ${attack.threat.type}`);
  console.log(`Keparahan    : ${attack.threat.severity}`); // "critical" | "high" | "medium" | "low"
});
```

### Membuat Endpoint Monitoring untuk Dashboard Website Anda:

```ts
// Express / Node.js
app.get('/api/admin/security-monitoring', (req, res) => {
  // Hanya admin yang boleh akses
  res.json({
    status: 'active',
    totalAttacksBlocked: guard.getThreatLogs().length,
    activeEndpoints: guard.getDiscoveredEndpoints(),
    recentAttacks: guard.getThreatLogs(20),
  });
});
```

---

## 🍯 Active Deception (Honeypot Trap) & Reputasi IP (Fail2Ban)

### 1. Honeypot Tripwire
NextGuard secara default memasang jebakan pada rute yang sering dicari oleh bot scanner otomatis:
- `/.env`, `/.env.local`
- `/.git/config`, `/.git/HEAD`
- `/wp-admin`, `/wp-login.php`
- `/phpmyadmin`, `/pma`
- `/.aws/credentials`, `/.ssh/id_rsa`
- `/actuator/health`, `/backup.sql`

Jika ada client yang mengakses rute-rute ini, **IP client tersebut 100% dipastikan bot scanner berbahaya** dan langsung **di-jail otomatis selama 24 jam**.

### 2. Reputasi Bertingkat (Fail2Ban Penalty)
Setiap ancaman menambahkan poin *strike*:
- Serangan Kritis (Command Injection, Honeypot, Prototype Pollution): Langsung di-jail!
- Serangan Berat (SQLi, NoSQLi, XSS, SSRF): +3 strikes.
- Durasi ban meningkat secara eksponensial bagi pelanggar berulang:
  - Pelanggaran ke-1: **15 menit**
  - Pelanggaran ke-2: **2 jam**
  - Pelanggaran ke-3: **24 jam**
  - Pelanggaran ke-4+: **7 hari penuh**

---

## 🔔 Integrasi Webhook (Discord / Slack)

Dapatkan notifikasi instan saat serangan berbahaya terjadi di server Anda:

```ts
const guard = NextGuard({
  telemetry: {
    enabled: true,
    // Cukup masukkan URL Webhook Discord atau Slack
    webhookUrl: 'https://discord.com/api/webhooks/123456789/abcdefgh',
  },
});
```

NextGuard otomatis mengirimkan embed kaya dengan rincian **IP Penyerang, Lokasi, Koordinat, Perangkat, Jenis Exploit, dan Target Endpoint**.

---

## ⚙️ Referensi Konfigurasi Lengkap

```ts
const guard = NextGuard({
  // Mode firewall: 'enforce' (blokir aktif) atau 'monitor' (hanya log)
  mode: 'enforce',

  // --- 1. Firewall 7 Lapis & Exploit Neutralizer ---
  sevenLayerShield: {
    enabled: true,
    neutralizeMode: 'synthetic_error', // 'synthetic_error' | 'abort_stream' | 'standard_block'
    blockDangerousMethods: true,        // Blokir TRACE, TRACK, CONNECT, DEBUG
    maxHeaderSizeBytes: 16384,          // Maks 16KB header (mencegah buffer overflow)
  },

  // --- 2. Anti-DDoS & Rate Limiting ---
  rateLimit: {
    enabled: true,
    windowMs: 60 * 1000,         // Jendela waktu (1 menit)
    max: 100,                    // Maks 100 request/menit
    jailThreshold: 200,          // Auto-jail jika mencapai 200 request
    jailDurationMs: 5 * 60 * 1000, // Durasi jail awal: 5 menit
  },

  // --- 3. Detektor Eksploitasi ---
  sqlInjection: { enabled: true, sensitivity: 'medium' },
  nosqlInjection: { enabled: true },
  xss: { enabled: true, sensitivity: 'medium' },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  prototypePollution: { enabled: true },
  ssrf: { enabled: true, blockCloudMetadata: true, blockLoopback: true },
  badBots: { enabled: true, knownScanners: true, blockEmptyUserAgent: true },

  // --- 4. Active Deception & Tarpit ---
  honeypot: { enabled: true, jailDurationMs: 24 * 60 * 60 * 1000 },
  reputation: { enabled: true, maxStrikes: 5 },
  tarpit: { enabled: false, delayMs: 3000 }, // Opsional: perlambat bot 3 detik

  // --- 5. IP Whitelist / Blacklist ---
  ipFilter: {
    whitelist: ['127.0.0.1', '192.168.1.0/24'], // IP aman
    blacklist: ['203.0.113.50'],                 // IP dilarang
  },

  // --- 6. Security Headers ---
  securityHeaders: {
    enabled: true,
    xFrameOptions: 'DENY',
    xContentTypeOptions: true,
    strictTransportSecurity: 'max-age=31536000; includeSubDomains',
  },

  // --- 7. Jalur yang Dilewati ---
  excludePaths: ['/_next/*', '/favicon.ico', '/public/*'],

  // --- 8. Event Callbacks ---
  onBlocked: (verdict, req) => {
    console.warn(`[BLOCKED] ${verdict.threatType} dari IP ${verdict.clientIp}`);
  },
});
```

---

## 🧪 Pengujian & Verifikasi

Proyek ini telah melalui pengujian menyeluruh dengan Vitest mencakup seluruh vektor ancaman:

```bash
npm test
```

```
 Test Files  19 passed (19)
      Tests  127 passed (127)
   Start at  06:50:09
   Duration  4.14s

 ✓ tests/seven-layer-shield.test.ts (12 tests)
 ✓ tests/node-package.test.ts (10 tests)
 ✓ tests/next-package.test.ts (11 tests)
 ✓ tests/telemetry.test.ts (8 tests)
 ✓ tests/sqli.test.ts (7 tests)
 ✓ tests/nosqli.test.ts (3 tests)
 ✓ tests/prototype-pollution.test.ts (4 tests)
 ✓ tests/ssrf.test.ts (4 tests)
 ✓ tests/command-injection.test.ts (4 tests)
 ✓ tests/xss.test.ts (6 tests)
 ✓ tests/honeypot.test.ts (3 tests)
 ✓ tests/reputation.test.ts (4 tests)
 ✓ tests/rate-limit.test.ts (4 tests)
 ✓ tests/bot.test.ts (4 tests)
 ✓ tests/ip-filter.test.ts (5 tests)
 ✓ tests/registry.test.ts (18 tests)
 ✓ tests/presets.test.ts (13 tests)
 ✓ tests/nextjs-middleware.test.ts (5 tests)
 ✓ tests/express.test.ts (2 tests)
```

---

## 📄 Lisensi

Didistribusikan di bawah Lisensi **MIT**. Bebas digunakan untuk keperluan komersial maupun pribadi.
Dibuat dengan ❤️ oleh tim pengembang **NextGuard**.
