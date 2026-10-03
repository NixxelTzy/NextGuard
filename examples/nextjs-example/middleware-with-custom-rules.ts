/**
 * Example: Custom Rules - Aturan Firewall Buatan Sendiri
 *
 * NextGuard mendukung aturan custom yang memungkinkan developer
 * membuat logika keamanan spesifik untuk kebutuhan bisnis mereka.
 */

import { createNextGuardMiddleware } from 'nextguard';
import type { RequestContext } from 'nextguard';

export const middleware = createNextGuardMiddleware({
  mode: 'enforce',

  // Aturan bawaan
  rateLimit: { max: 100, windowMs: 60 * 1000 },
  sqlInjection: { enabled: true },
  xss: { enabled: true },

  // -----------------------------------------------------------------------
  // Custom Rules - Bisa ditambah sebanyak yang dibutuhkan
  // -----------------------------------------------------------------------
  customRules: [
    // Aturan 1: Blokir request dari country tertentu berdasarkan IP range
    {
      name: 'block_suspicious_ip_range',
      description: 'Blokir IP range dari jaringan yang dikenal berbahaya',
      evaluate: (req: RequestContext) => {
        const ip = req.ip;
        const blockedRanges = ['45.142.212.', '195.54.161.'];
        return blockedRanges.some(prefix => ip.startsWith(prefix));
      },
      action: 'block',
      statusCode: 403,
      reason: 'Request dari IP range yang tidak diizinkan',
    },

    // Aturan 2: Wajib ada Authorization header untuk /api/protected/*
    {
      name: 'require_auth_header',
      description: 'Endpoint terproteksi wajib memiliki Authorization header',
      evaluate: (req: RequestContext) => {
        if (!req.url.includes('/api/protected/')) return false;
        const authHeader = req.headers['authorization'];
        return !authHeader || !authHeader.startsWith('Bearer ');
      },
      action: 'block',
      statusCode: 401,
      reason: 'Authorization header tidak valid atau tidak ada',
    },

    // Aturan 3: Blokir request body yang menyertakan kata kunci tertentu
    {
      name: 'block_banned_keywords',
      description: 'Deteksi konten spam atau terlarang dalam body',
      evaluate: (req: RequestContext) => {
        const bannedKeywords = ['cryptocurrency', 'free-money', 'click-here-now'];
        const bodyStr = JSON.stringify(req.body || '').toLowerCase();
        return bannedKeywords.some(kw => bodyStr.includes(kw));
      },
      action: 'block',
      statusCode: 403,
      reason: 'Request body mengandung konten terlarang',
    },

    // Aturan 4: Monitor-only (catat tapi tidak blokir) untuk path sensitif
    {
      name: 'monitor_admin_access',
      description: 'Catat semua akses ke path admin',
      evaluate: (req: RequestContext) => {
        return req.url.startsWith('/api/admin');
      },
      action: 'monitor', // Hanya log, tidak blokir
      reason: 'Admin path access logged',
    },

    // Aturan 5: Validasi Content-Type untuk POST/PUT requests
    {
      name: 'validate_content_type',
      description: 'Request POST/PUT harus memiliki Content-Type: application/json',
      evaluate: (req: RequestContext) => {
        if (!['POST', 'PUT', 'PATCH'].includes(req.method.toUpperCase())) return false;
        if (req.url.startsWith('/_next/') || req.url.startsWith('/api/upload/')) return false;
        const ct = req.headers['content-type'] as string | undefined;
        return !ct || !ct.includes('application/json');
      },
      action: 'block',
      statusCode: 415,
      reason: 'Content-Type harus application/json untuk method ini',
    },

    // Aturan 6: Async rule - cek ke database/Redis blacklist
    {
      name: 'async_ip_reputation_check',
      description: 'Cek reputasi IP dari external threat intelligence (contoh async)',
      evaluate: async (req: RequestContext): Promise<boolean> => {
        // Simulasi pengecekan ke external API / Redis / DB
        // Dalam produksi, ganti dengan pengecekan nyata ke threat intel feed
        const knownMaliciousIps = new Set(['1.2.3.4', '5.6.7.8']);
        return knownMaliciousIps.has(req.ip);
      },
      action: 'block',
      statusCode: 403,
      reason: 'IP terdeteksi dalam daftar hitam reputasi',
    },
  ],

  onBlocked: (verdict, req) => {
    if (verdict.threatType === 'custom_rule_violation') {
      console.warn(`[CUSTOM RULE] Rule triggered for IP ${verdict.clientIp}: ${verdict.reason}`);
    }
  },
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
