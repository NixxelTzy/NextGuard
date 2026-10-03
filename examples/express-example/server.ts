/**
 * Example: Node.js Express.js Application
 * Menggunakan NextGuard sebagai middleware global + per-route overrides
 *
 * Install:
 * npm install express nextguard
 * npm install -D @types/express
 */

import express from 'express';
import { nextGuardExpress, MemoryStore } from 'nextguard';

const app = express();
app.use(express.json());

// -----------------------------------------------------------------------
// 1. Global Firewall - Berlaku untuk semua route
// -----------------------------------------------------------------------
const globalFirewall = nextGuardExpress({
  mode: 'enforce',

  // Rate Limiting global (100 req/menit)
  rateLimit: {
    windowMs: 60 * 1000,
    max: 100,
    jailThreshold: 200,
    jailDurationMs: 5 * 60 * 1000,
    store: new MemoryStore(),
  },

  // Semua proteksi diaktifkan secara global
  sqlInjection: { enabled: true, sensitivity: 'medium' },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { blockEmptyUserAgent: false, knownScanners: true },

  // IP Blacklist
  ipFilter: {
    blacklist: ['192.0.2.0/24'],
    trustProxy: true,
  },

  // Security Headers pada semua response
  securityHeaders: {
    enabled: true,
    xFrameOptions: 'DENY',
    strictTransportSecurity: 'max-age=31536000; includeSubDomains',
  },

  // Custom logging untuk semua security events
  onBlocked: (verdict) => {
    console.error(`[WAF BLOCKED] ${new Date().toISOString()} | IP: ${verdict.clientIp} | Threat: ${verdict.threatType} | Reason: ${verdict.reason} | RequestID: ${verdict.requestId}`);
  },

  // Exclude health check dari firewall
  excludePaths: ['/health'],
});

// Terapkan firewall secara global
app.use(globalFirewall);

// -----------------------------------------------------------------------
// 2. Route-specific overrides menggunakan endpoint firewall tambahan
// -----------------------------------------------------------------------

// Login endpoint - Rate limit ekstra ketat
const strictLoginFirewall = nextGuardExpress({
  rateLimit: {
    windowMs: 60 * 1000,
    max: 5, // Hanya 5 percobaan login per menit
    jailDurationMs: 15 * 60 * 1000,
  },
});

app.post('/api/login', strictLoginFirewall, async (req, res) => {
  const { username, password } = req.body;
  // ... validasi credentials
  res.json({ token: 'sample-jwt-token' });
});

// Search endpoint - Hanya perlu query protection, rate limit longgar
const searchFirewall = nextGuardExpress({
  rateLimit: { max: 300, windowMs: 60 * 1000 },
  sqlInjection: { enabled: true, inspectQuery: true },
  xss: false,
  commandInjection: false,
});

app.get('/api/search', searchFirewall, (req, res) => {
  const { q } = req.query;
  res.json({ results: [], query: q });
});

// Admin panel - Hanya IP whitelist yang boleh akses
const adminFirewall = nextGuardExpress({
  ipFilter: {
    whitelist: ['10.0.0.0/8', '127.0.0.1'],
  },
  rateLimit: { max: 50, windowMs: 60 * 1000 },
  mode: 'enforce',
});

app.use('/api/admin', adminFirewall, (req, res) => {
  res.json({ admin: true });
});

// Health check - tidak terproteksi (sudah di-exclude global)
app.get('/health', (_, res) => {
  res.json({ status: 'ok' });
});

// -----------------------------------------------------------------------
// 3. Start server
// -----------------------------------------------------------------------
app.listen(3000, () => {
  console.log('[NextGuard] Express server running on http://localhost:3000');
});
