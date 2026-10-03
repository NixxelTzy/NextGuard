/**
 * security/login.ts
 *
 * Konfigurasi keamanan untuk endpoint Login / Sign In.
 * File ini dibuat oleh DEVELOPER di proyek mereka sendiri.
 *
 * Cara pakai:
 *   import loginSecurity from '@/security/login';
 *   export const POST = withGuard(handler, loginSecurity);
 *   // atau digabung dengan global:
 *   export const POST = withGuard(handler, mergeGuard(globalSecurity, loginSecurity));
 */

import { defineEndpointSecurity } from 'nextguard';

export default defineEndpointSecurity({
  $name: 'login',
  $description: 'Proteksi endpoint login - anti brute force & SQL Injection',
  $tags: ['auth', 'critical'],

  mode: 'enforce',

  rateLimit: {
    windowMs: 60 * 1000,
    max: 5,                         // Hanya 5 percobaan per menit
    jailThreshold: 10,
    jailDurationMs: 15 * 60 * 1000, // Ban 15 menit jika flooding
  },

  sqlInjection:     { enabled: true, sensitivity: 'high', inspectBody: true, inspectQuery: true },
  xss:              { enabled: true, sensitivity: 'high' },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true },

  payloadGuard: { enabled: true, maxBodySize: 10 * 1024 }, // Maks 10KB

  onBlocked: (verdict, req) => {
    if (verdict.threatType === 'rate_limit_exceeded') {
      console.warn(`[BRUTE FORCE] Login attack dari IP: ${verdict.clientIp}`);
    }
  },
});
