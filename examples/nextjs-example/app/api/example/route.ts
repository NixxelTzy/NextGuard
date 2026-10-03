/**
 * Example: Next.js App Router Route Handler
 * File: app/api/contact/route.ts
 *
 * Each endpoint bisa punya konfigurasi firewall berbeda:
 * - Login endpoint: Rate limit ketat
 * - Upload endpoint: Payload guard yang lebih longgar
 * - Public endpoint: Aturan standar
 */

import { withNextGuard } from 'nextguard';

// =====================================================================
// Endpoint 1: Login - Rate limit sangat ketat + semua proteksi
// =====================================================================
async function loginHandler(req: Request): Promise<Response> {
  const body = await req.json();
  // ... logic login
  return Response.json({ token: 'xxx' });
}

export const POST = withNextGuard(loginHandler, {
  rateLimit: {
    windowMs: 60 * 1000,   // 1 menit
    max: 5,                  // Maksimal 5 percobaan login per menit
    jailThreshold: 10,
    jailDurationMs: 15 * 60 * 1000, // Banned 15 menit jika flooding
  },
  sqlInjection: { enabled: true, sensitivity: 'high' },
  xss: { enabled: true },
  badBots: { blockEmptyUserAgent: true },
  onBlocked: (verdict) => {
    // Kirim alert ke tim keamanan
    console.error(`[BRUTE FORCE] Login attack from ${verdict.clientIp}`);
  },
});

// =====================================================================
// Endpoint 2: File Upload - Payload size limit yang lebih besar
// =====================================================================
async function uploadHandler(req: Request): Promise<Response> {
  // ... logic upload
  return Response.json({ uploaded: true });
}

export const PUT = withNextGuard(uploadHandler, {
  payloadGuard: {
    enabled: true,
    maxBodySize: 50 * 1024 * 1024, // 50MB untuk upload
  },
  rateLimit: {
    windowMs: 60 * 1000,
    max: 20, // Batas wajar untuk upload
  },
});

// =====================================================================
// Endpoint 3: Public API - Konfigurasi default, hanya rate limit
// =====================================================================
async function publicHandler(req: Request): Promise<Response> {
  const { searchParams } = new URL(req.url);
  const query = searchParams.get('q') || '';
  return Response.json({ results: [], query });
}

export const GET = withNextGuard(publicHandler, {
  rateLimit: {
    windowMs: 60 * 1000,
    max: 200, // Lebih longgar untuk endpoint publik
  },
});
