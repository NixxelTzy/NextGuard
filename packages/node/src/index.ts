/**
 * @nextguard/node
 *
 * Single-install middleware untuk Node.js / Express / Fastify / Connect.
 *
 * Pengguna hanya pasang SATU KALI di server utama:
 *
 *   import { NextGuard } from '@nextguard/node';
 *   const guard = NextGuard({ apiKey: process.env.NEXTGUARD_KEY });
 *   app.use(guard.middleware());
 *
 * Setelah itu SEMUA route yang ada di bawahnya otomatis terlindungi.
 * Tidak perlu import NextGuard di setiap file route.
 *
 * Endpoint ditemukan otomatis dari request aktual yang melewati middleware.
 * Tidak ada scan source code, tidak ada daftar manual.
 */

// ─── Import dari core NextGuard yang sudah ada (TIDAK diubah) ───────────────
// Dalam monorepo: import langsung dari src core nextguard
import { NextGuardEngine } from '../../../src/core/engine.js';
import { EndpointRegistry, normalizePath } from '../../../src/registry.js';
import { getSecurityHeaders } from '../../../src/security/headers.js';
import { renderBlockedHtml, renderBlockedJson } from '../../../src/templates/blocked-page.js';
import type { NextGuardConfig, RequestContext, InspectionVerdict } from '../../../src/types.js';

// ─── Public types ────────────────────────────────────────────────────────────

export interface NodeGuardOptions extends NextGuardConfig {
  /**
   * API key untuk NextGuard (opsional — untuk dashboard/telemetry cloud).
   * Jika tidak diset, semua data tersimpan di memory lokal.
   */
  apiKey?: string;

  /**
   * Nama aplikasi (opsional) — muncul di telemetry/log.
   */
  appName?: string;

  /**
   * Aktifkan logging console bawaan untuk setiap event firewall.
   * Default: true
   */
  logging?: boolean;

  /**
   * Path yang dikecualikan dari firewall sepenuhnya (tidak di-inspect, tidak dicatat).
   * Sudah di-merge dengan excludePaths dari NextGuardConfig.
   */
  skipPaths?: (string | RegExp)[];
}

export interface GuardInstance {
  /**
   * Middleware untuk Express / Connect / Fastify.
   * Pasang SATU KALI di server utama.
   *
   * @example
   * app.use(guard.middleware());
   */
  middleware(): ExpressMiddleware;

  /**
   * Override konfigurasi firewall untuk satu endpoint tertentu.
   * OPSIONAL — endpoint tetap dilindungi global tanpa ini.
   *
   * @example
   * guard.protect('/api/login', { rateLimit: { max: 5 } });
   */
  protect(path: string, override: Partial<NextGuardConfig>): void;

  /**
   * Ambil daftar semua endpoint yang sudah ditemukan dari traffic aktual.
   */
  getDiscoveredEndpoints(): ReturnType<EndpointRegistry['getAll']>;

  /**
   * Statistik ringkasan semua endpoint.
   */
  getStats(): ReturnType<EndpointRegistry['getStats']>;

  /**
   * Registry internal (untuk akses penuh jika perlu).
   */
  readonly registry: EndpointRegistry;
}

export type ExpressMiddleware = (req: any, res: any, next: (err?: any) => void) => Promise<void>;

// ─── Implementasi ─────────────────────────────────────────────────────────────

/**
 * Buat instance NextGuard untuk Node.js / Express.
 *
 * @example
 * import express from 'express';
 * import { NextGuard } from '@nextguard/node';
 *
 * const app = express();
 * const guard = NextGuard({ apiKey: process.env.NEXTGUARD_KEY });
 * app.use(guard.middleware());
 *
 * // Routes di bawah ini otomatis terlindungi — tidak perlu import NextGuard di sini
 * app.get('/api/users', handler);
 * app.post('/api/upload', handler);
 * app.post('/api/payment', handler);
 */
export function NextGuard(options: NodeGuardOptions = {}): GuardInstance {
  const {
    apiKey,
    appName = 'app',
    logging = true,
    skipPaths = [],
    ...engineConfig
  } = options;

  // Merge skipPaths dengan excludePaths dari config
  const mergedConfig: NextGuardConfig = {
    ...engineConfig,
    excludePaths: [
      ...(engineConfig.excludePaths ?? []),
      ...skipPaths,
    ],
  };

  // Inisialisasi security engine yang SUDAH ADA — tidak membuat engine baru
  const engine = new NextGuardEngine(mergedConfig);
  const secHeaders = getSecurityHeaders(mergedConfig.securityHeaders);

  // Registry untuk endpoint discovery dari traffic aktual
  const registry = new EndpointRegistry();

  // Per-endpoint override config (opsional, diisi lewat guard.protect())
  const endpointOverrides = new Map<string, Partial<NextGuardConfig>>();

  // ── Log helper ──────────────────────────────────────────────────────────────
  function log(level: 'info' | 'warn' | 'error', message: string): void {
    if (!logging) return;
    const prefix = `[NextGuard${appName ? `:${appName}` : ''}]`;
    const ts = new Date().toISOString();
    if (level === 'error') console.error(`${prefix} ${ts} ERROR ${message}`);
    else if (level === 'warn') console.warn(`${prefix} ${ts} WARN  ${message}`);
    else console.log(`${prefix} ${ts} INFO  ${message}`);
  }

  // ── Resolve engine: global atau per-endpoint override ─────────────────────
  function getEngine(path: string): NextGuardEngine {
    // Cek apakah ada override config untuk path ini
    const override = endpointOverrides.get(path);
    if (override) {
      // Merge global config dengan override — buat engine sementara
      return new NextGuardEngine({ ...mergedConfig, ...override });
    }
    return engine;
  }

  // ── Middleware utama ───────────────────────────────────────────────────────
  function middleware(): ExpressMiddleware {
    return async function nextGuardMiddleware(req: any, res: any, next: (err?: any) => void): Promise<void> {
      try {
        // 1. Normalisasi headers
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(req.headers || {})) {
          headers[key.toLowerCase()] = Array.isArray(value) ? (value as string[])[0] : (value as string);
        }

        // 2. Resolve client IP
        const ip =
          headers['cf-connecting-ip'] ||
          headers['x-real-ip'] ||
          (headers['x-forwarded-for'] ? headers['x-forwarded-for'].split(',')[0].trim() : undefined) ||
          req.ip ||
          req.socket?.remoteAddress ||
          '127.0.0.1';

        // 3. Normalisasi path & buat RequestContext
        const rawUrl = req.originalUrl || req.url || '/';
        const path = normalizePath(rawUrl);
        const method = (req.method || 'GET').toUpperCase();

        // Parse query params (pakai req.query jika ada, fallback parsing dari rawUrl)
        let query: Record<string, unknown> | undefined = req.query;
        if (!query || Object.keys(query).length === 0) {
          try {
            const parsedUrl = rawUrl.startsWith('http') ? new URL(rawUrl) : new URL(rawUrl, 'http://localhost');
            const q: Record<string, string> = {};
            parsedUrl.searchParams.forEach((val, key) => { q[key] = val; });
            if (Object.keys(q).length > 0) query = q;
          } catch {}
        }

        const ctx: RequestContext = {
          url: rawUrl,
          method,
          ip,
          headers,
          query,
          body: req.body,
        };

        // 4. Pilih engine (global atau per-endpoint override)
        const activeEngine = getEngine(path);

        // 5. Jalankan security engine yang SUDAH ADA
        const verdict: InspectionVerdict = await activeEngine.inspect(ctx);

        // 6. Catat endpoint yang ditemukan dari traffic aktual (kecualikan excluded paths)
        const isExcluded = mergedConfig.excludePaths?.some(p => {
          if (p instanceof RegExp) return p.test(path);
          if (typeof p === 'string' && p.endsWith('*')) return path.startsWith(p.slice(0, -1));
          return p === path;
        });

        if (!isExcluded) {
          registry.record(method, rawUrl, ip, verdict.allowed, verdict.statusCode);
        }

        // 7. Set security headers pada semua response
        for (const [name, value] of Object.entries(secHeaders)) {
          res.setHeader(name, value);
        }

        // 8. Tangani hasil firewall
        if (!verdict.allowed) {
          if (logging && verdict.threatType) {
            log('warn',
              `BLOCKED ${method} ${path} | ` +
              `threat=${verdict.threatType} | ` +
              `ip=${ip} | ` +
              `reason="${verdict.reason}" | ` +
              `reqId=${verdict.requestId}`
            );
          }

          const accept = headers['accept'] || '';
          const isHtml = mergedConfig.htmlResponse && accept.includes('text/html');

          if (isHtml) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.status(verdict.statusCode).send(renderBlockedHtml(verdict));
            return;
          }

          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.status(verdict.statusCode).json(renderBlockedJson(verdict));
          return;
        }

        // 9. Request aman — teruskan ke route handler
        next();

      } catch (err) {
        next(err);
      }
    };
  }

  // ── guard.protect() — per-endpoint override (OPSIONAL) ────────────────────
  function protect(path: string, override: Partial<NextGuardConfig>): void {
    const normalizedPath = path.startsWith('/') ? path.toLowerCase() : `/${path.toLowerCase()}`;
    endpointOverrides.set(normalizedPath, override);
    log('info', `Custom protection registered for: ${normalizedPath}`);
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  return {
    middleware,
    protect,
    getDiscoveredEndpoints: () => registry.getAll(),
    getStats: () => registry.getStats(),
    registry,
  };
}

// Re-export types yang berguna untuk pengguna
export type { NextGuardConfig, RequestContext, InspectionVerdict } from '../../../src/types.js';
export { EndpointRegistry } from '../../../src/registry.js';
