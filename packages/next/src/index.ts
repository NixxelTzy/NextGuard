/**
 * @nextguard/next
 *
 * Single-install middleware untuk Next.js via middleware.ts.
 *
 * Pengguna hanya pasang SATU KALI di middleware.ts:
 *
 *   import { NextGuard } from '@nextguard/next';
 *   const guard = NextGuard({ apiKey: process.env.NEXTGUARD_KEY });
 *   export default guard.middleware();
 *   export const config = { matcher: '/:path*' };
 *
 * Semua route Next.js (App Router & Pages Router) otomatis terlindungi.
 * Tidak perlu import NextGuard di setiap route.ts / page.ts.
 *
 * Endpoint ditemukan otomatis dari request yang benar-benar masuk.
 */

// ─── Import dari core NextGuard yang sudah ada (TIDAK diubah) ───────────────
import { NextGuardEngine } from '../../../src/core/engine.js';
import { EndpointRegistry, normalizePath } from '../../../src/registry.js';
import { getSecurityHeaders } from '../../../src/security/headers.js';
import { renderBlockedHtml, renderBlockedJson } from '../../../src/templates/blocked-page.js';
import {
  extractRequestContext,
  GenericNextRequest,
} from '../../../src/middleware/nextjs.js';
import type { NextGuardConfig, InspectionVerdict } from '../../../src/types.js';

// ─── Public types ─────────────────────────────────────────────────────────────

export interface NextGuardOptions extends NextGuardConfig {
  /**
   * API key untuk NextGuard dashboard/telemetry (opsional).
   */
  apiKey?: string;

  /**
   * Nama aplikasi (opsional).
   */
  appName?: string;

  /**
   * Aktifkan console logging. Default: true
   */
  logging?: boolean;

  /**
   * Path yang sepenuhnya dilewati (tidak di-inspect, tidak dicatat).
   */
  skipPaths?: (string | RegExp)[];
}

export interface NextGuardInstance {
  /**
   * Handler untuk Next.js middleware.ts.
   * Kembalikan fungsi ini sebagai export default di middleware.ts.
   *
   * @example
   * // middleware.ts
   * export default guard.middleware();
   * export const config = { matcher: '/:path*' };
   */
  middleware(): NextMiddlewareHandler;

  /**
   * Override konfigurasi untuk satu path/endpoint tertentu (OPSIONAL).
   * Endpoint tetap dilindungi global tanpa ini.
   *
   * @example
   * guard.protect('/api/login', { rateLimit: { max: 5 } });
   */
  protect(path: string, override: Partial<NextGuardConfig>): void;

  /**
   * Ambil semua endpoint yang sudah ditemukan dari traffic aktual.
   */
  getDiscoveredEndpoints(): ReturnType<EndpointRegistry['getAll']>;

  /**
   * Statistik ringkasan.
   */
  getStats(): ReturnType<EndpointRegistry['getStats']>;

  /** Registry internal */
  readonly registry: EndpointRegistry;
}

/**
 * Tipe handler yang kompatibel dengan Next.js middleware.ts.
 * Menerima Request (Web API standard), mengembalikan Response | undefined.
 * Jika undefined → request diteruskan ke route handler.
 */
export type NextMiddlewareHandler = (
  req: Request | GenericNextRequest
) => Promise<Response | undefined>;

// ─── Implementasi ─────────────────────────────────────────────────────────────

/**
 * Buat instance NextGuard untuk Next.js.
 *
 * @example
 * // middleware.ts  ← SATU-SATUNYA file yang perlu diubah
 * import { NextGuard } from '@nextguard/next';
 *
 * const guard = NextGuard({
 *   apiKey: process.env.NEXTGUARD_KEY,
 *   rateLimit: { max: 100, windowMs: 60_000 },
 * });
 *
 * export default guard.middleware();
 *
 * export const config = {
 *   matcher: '/:path*',  // tangkap semua request
 * };
 *
 * // app/api/users/route.ts — TIDAK perlu import apapun dari NextGuard
 * export async function GET(req: Request) {
 *   return Response.json({ users: [] });
 * }
 *
 * // app/api/upload/route.ts — TIDAK perlu import apapun dari NextGuard
 * export async function POST(req: Request) {
 *   return Response.json({ ok: true });
 * }
 */
export function NextGuard(options: NextGuardOptions = {}): NextGuardInstance {
  const {
    apiKey,
    appName = 'next-app',
    logging = true,
    skipPaths = [],
    ...engineConfig
  } = options;

  const mergedConfig: NextGuardConfig = {
    ...engineConfig,
    excludePaths: [
      // Default: kecualikan asset statis Next.js
      '/_next/*',
      '/favicon.ico',
      '/robots.txt',
      '/sitemap.xml',
      ...(engineConfig.excludePaths ?? []),
      ...skipPaths,
    ],
  };

  // Engine security yang sudah ada
  const engine = new NextGuardEngine(mergedConfig);
  const secHeaders = getSecurityHeaders(mergedConfig.securityHeaders);

  // Registry untuk auto-discovery dari traffic
  const registry = new EndpointRegistry();

  // Per-endpoint overrides (diisi lewat guard.protect())
  const endpointOverrides = new Map<string, Partial<NextGuardConfig>>();

  function log(level: 'info' | 'warn' | 'error', message: string): void {
    if (!logging) return;
    const prefix = `[NextGuard:${appName}]`;
    const ts = new Date().toISOString();
    if (level === 'error') console.error(`${prefix} ${ts} ERROR ${message}`);
    else if (level === 'warn') console.warn(`${prefix} ${ts} WARN  ${message}`);
    else console.log(`${prefix} ${ts} INFO  ${message}`);
  }

  function getEngine(path: string): NextGuardEngine {
    const override = endpointOverrides.get(path);
    if (override) {
      return new NextGuardEngine({ ...mergedConfig, ...override });
    }
    return engine;
  }

  // ── Middleware utama ───────────────────────────────────────────────────────
  function middleware(): NextMiddlewareHandler {
    return async function nextGuardHandler(
      req: Request | GenericNextRequest
    ): Promise<Response | undefined> {

      // 1. Ekstrak RequestContext menggunakan fungsi yang sudah ada di nextjs.ts
      //    Tidak inspect body di middleware (body consumption harus di route handler)
      const ctx = await extractRequestContext(req as GenericNextRequest, false);

      const path = normalizePath(ctx.url);
      const method = ctx.method.toUpperCase();

      // 2. Pilih engine (global atau per-endpoint override jika ada)
      const activeEngine = getEngine(path);

      // 3. Jalankan security engine yang sudah ada
      const verdict: InspectionVerdict = await activeEngine.inspect(ctx);

      // 4. Catat endpoint dari traffic aktual (kecualikan excluded paths)
      const isExcluded = mergedConfig.excludePaths?.some(p => {
        if (p instanceof RegExp) return p.test(path);
        if (typeof p === 'string' && p.endsWith('*')) return path.startsWith(p.slice(0, -1));
        return p === path;
      });

      if (!isExcluded) {
        registry.record(method, ctx.url, ctx.ip, verdict.allowed, verdict.statusCode);
      }

      // 5. Tangani hasil firewall
      if (!verdict.allowed) {
        if (logging && verdict.threatType) {
          log('warn',
            `BLOCKED ${method} ${path} | ` +
            `threat=${verdict.threatType} | ` +
            `ip=${ctx.ip} | ` +
            `reason="${verdict.reason}" | ` +
            `reqId=${verdict.requestId}`
          );
        }

        // Buat security headers untuk response blocked
        const blockedHeaders = new Headers(secHeaders as Record<string, string>);

        const accept = ctx.headers['accept'] || '';
        const wantsHtml = mergedConfig.htmlResponse !== false && typeof accept === 'string' && accept.includes('text/html');

        if (wantsHtml) {
          blockedHeaders.set('Content-Type', 'text/html; charset=utf-8');
          return new Response(renderBlockedHtml(verdict), {
            status: verdict.statusCode,
            headers: blockedHeaders,
          });
        }

        blockedHeaders.set('Content-Type', 'application/json; charset=utf-8');
        return new Response(JSON.stringify(renderBlockedJson(verdict)), {
          status: verdict.statusCode,
          headers: blockedHeaders,
        });
      }

      // 6. Request aman → kembalikan undefined agar Next.js meneruskan ke route handler
      //    (NextResponse.next() tidak dipakai agar tidak ada dependency ke 'next/server')
      return undefined;
    };
  }

  function protect(path: string, override: Partial<NextGuardConfig>): void {
    const normalizedPath = path.startsWith('/') ? path.toLowerCase() : `/${path.toLowerCase()}`;
    endpointOverrides.set(normalizedPath, override);
    log('info', `Custom protection registered for path: ${normalizedPath}`);
  }

  return {
    middleware,
    protect,
    getDiscoveredEndpoints: () => registry.getAll(),
    getStats: () => registry.getStats(),
    registry,
  };
}

export type { NextGuardConfig, NextGuardOptions, InspectionVerdict } from '../../../src/types.js';
export { EndpointRegistry, normalizePath } from '../../../src/registry.js';
