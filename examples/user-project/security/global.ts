/**
 * security/global.ts
 *
 * Konfigurasi GLOBAL — berlaku untuk semua endpoint.
 * File ini dibuat oleh developer di proyek mereka sendiri.
 *
 * Di-import ke middleware.ts dan di-merge dengan config per-endpoint.
 */

import { defineEndpointSecurity } from 'nextguard';

export default defineEndpointSecurity({
  $name: 'global',
  $description: 'Konfigurasi keamanan dasar untuk semua endpoint',
  $tags: ['global'],

  mode: 'enforce',

  // Rate limit default (per endpoint bisa di-override)
  rateLimit: {
    windowMs: 60 * 1000,
    max: 150,
    jailThreshold: 300,
    jailDurationMs: 5 * 60 * 1000,
  },

  // Semua deteksi aktif secara global
  sqlInjection:     { enabled: true, sensitivity: 'medium' },
  xss:              { enabled: true, sensitivity: 'medium' },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true },
  badBots:          { enabled: true, knownScanners: true },

  // IP yang boleh diakses semua endpoint
  ipFilter: {
    whitelist: ['127.0.0.1'],
    trustProxy: true,
  },

  // Security headers pada semua response
  securityHeaders: {
    enabled: true,
    xFrameOptions: 'DENY',
    xContentTypeOptions: true,
    strictTransportSecurity: 'max-age=31536000; includeSubDomains',
    referrerPolicy: 'strict-origin-when-cross-origin',
  },

  // Kecualikan asset statis Next.js
  excludePaths: ['/_next/*', '/favicon.ico', '/robots.txt', '/sitemap.xml'],

  // Logging terpusat untuk semua event security
  onBlocked: (verdict) => {
    console.error(
      `[SECURITY] ${new Date().toISOString()} | ` +
      `${(verdict.threatType ?? 'unknown').toUpperCase()} | ` +
      `IP: ${verdict.clientIp} | ` +
      `Reason: ${verdict.reason} | ` +
      `ReqID: ${verdict.requestId}`
    );
  },
});
