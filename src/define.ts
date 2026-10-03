/**
 * NextGuard - Security Definition API
 *
 * API yang memungkinkan developer mendefinisikan konfigurasi keamanan
 * di luar package nextguard (di proyek mereka sendiri),
 * lalu menerapkannya secara fleksibel ke endpoint mana saja di platform mana saja.
 *
 * Alur:
 *   1. Developer buat file di proyek sendiri: security/login.ts
 *   2. Di sana mereka `defineEndpointSecurity({ ... })`
 *   3. Import dan pakai di route mana saja (Next.js, Express, Fastify, dll)
 *   4. Bisa di-merge/compose dengan config global
 */

import { NextGuardConfig, RateLimitConfig, SQLiConfig, XSSConfig } from './types.js';

// ─────────────────────────────────────────────────────────────────────────────
// TYPE: Security Definition (config + metadata)
// ─────────────────────────────────────────────────────────────────────────────

export interface SecurityDefinition extends NextGuardConfig {
  /** Nama identitas endpoint ini (opsional, untuk logging/debugging) */
  readonly $name?: string;
  /** Deskripsi singkat tujuan security config ini */
  readonly $description?: string;
  /** Tag kategori, misal: 'auth', 'payment', 'public' */
  readonly $tags?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// CORE: defineEndpointSecurity()
//
// Fungsi utama untuk mendefinisikan konfigurasi keamanan endpoint.
// Developer panggil ini di file security mereka sendiri.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Mendefinisikan konfigurasi keamanan untuk satu endpoint.
 * Hasilnya bisa langsung dipakai di withNextGuard(), nextGuardExpress(), dll.
 *
 * @example
 * // security/login.ts  <-- file ini ada di proyek pengguna, bukan di nextguard
 * export default defineEndpointSecurity({
 *   $name: 'login',
 *   rateLimit: { max: 5, windowMs: 60_000 },
 *   sqlInjection: { sensitivity: 'high' },
 * });
 */
export function defineEndpointSecurity(config: SecurityDefinition): SecurityDefinition {
  return Object.freeze({ ...config });
}

// ─────────────────────────────────────────────────────────────────────────────
// CORE: mergeGuard()
//
// Deep merge beberapa SecurityDefinition menjadi satu.
// Config yang datang belakangan override yang sebelumnya (kecuali array → digabung).
// Biasanya: mergeGuard(globalSecurity, endpointSecurity)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Menggabungkan beberapa konfigurasi keamanan menjadi satu.
 * Config paling kanan punya prioritas tertinggi.
 *
 * @example
 * // middleware.ts
 * import global from '@/security/global';
 * import login  from '@/security/login';
 *
 * export const middleware = createNextGuardMiddleware(mergeGuard(global, login));
 *
 * @example
 * // app/api/login/route.ts
 * export const POST = withNextGuard(handler, mergeGuard(global, loginSecurity));
 */
export function mergeGuard(...configs: SecurityDefinition[]): SecurityDefinition {
  const result: Record<string, unknown> = {};

  for (const config of configs) {
    for (const [key, value] of Object.entries(config)) {
      // Skip metadata fields, they get merged separately below
      if (key.startsWith('$')) continue;

      const existing = result[key];

      if (value === false) {
        // Explicitly disable a feature (false overrides anything)
        result[key] = false;
      } else if (value === undefined) {
        // Undefined doesn't override existing value
        continue;
      } else if (
        typeof value === 'object' &&
        value !== null &&
        !Array.isArray(value) &&
        typeof existing === 'object' &&
        existing !== null &&
        !Array.isArray(existing)
      ) {
        // Deep merge objects (e.g. rateLimit, sqlInjection config)
        result[key] = { ...(existing as object), ...(value as object) };
      } else if (Array.isArray(value) && Array.isArray(existing)) {
        // Merge arrays (e.g. customRules, excludePaths)
        result[key] = [...existing, ...value];
      } else {
        result[key] = value;
      }
    }
  }

  // Merge metadata: collect all tags, use last name/description
  const names: string[] = [];
  const tags: string[] = [];
  let description = '';

  for (const config of configs) {
    if (config.$name) names.push(config.$name);
    if (config.$description) description = config.$description;
    if (config.$tags) tags.push(...config.$tags);
  }

  if (names.length > 0) (result as any).$name = names.join('+');
  if (description) (result as any).$description = description;
  if (tags.length > 0) (result as any).$tags = [...new Set(tags)];

  return Object.freeze(result as SecurityDefinition);
}

// ─────────────────────────────────────────────────────────────────────────────
// CORE: createGuardGroup()
//
// Membuat "grup" firewall dari satu base config.
// Grup bisa meng-extend dirinya untuk kasus endpoint spesifik.
// Berguna untuk membuat satu guard yang dipakai di banyak route serupa.
// ─────────────────────────────────────────────────────────────────────────────

export interface GuardGroup {
  /** Konfigurasi dasar grup ini */
  readonly base: SecurityDefinition;
  /**
   * Extends config dasar dengan override tambahan.
   * Hasilnya adalah SecurityDefinition baru (tidak mengubah base).
   */
  extend(overrides: SecurityDefinition): SecurityDefinition;
  /**
   * Gabungkan grup ini dengan SecurityDefinition lain.
   */
  merge(...others: SecurityDefinition[]): SecurityDefinition;
}

/**
 * Membuat GuardGroup dari base config.
 * Cocok untuk kelompok endpoint yang berbagi aturan dasar
 * tapi masing-masing punya penyesuaian kecil.
 *
 * @example
 * // security/auth.group.ts
 * export const authGuard = createGuardGroup(defineEndpointSecurity({
 *   $name: 'auth',
 *   badBots: { blockEmptyUserAgent: true },
 *   sqlInjection: { sensitivity: 'high' },
 * }));
 *
 * // security/login.ts
 * export default authGuard.extend({ rateLimit: { max: 5 } });
 *
 * // security/register.ts
 * export default authGuard.extend({ rateLimit: { max: 3, windowMs: 600_000 } });
 */
export function createGuardGroup(base: SecurityDefinition): GuardGroup {
  return {
    base: Object.freeze({ ...base }),
    extend(overrides: SecurityDefinition): SecurityDefinition {
      return mergeGuard(base, overrides);
    },
    merge(...others: SecurityDefinition[]): SecurityDefinition {
      return mergeGuard(base, ...others);
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PLATFORM ADAPTERS: applyGuard()
//
// Universal adapter — mendeteksi platform secara otomatis dan mengembalikan
// middleware/wrapper yang tepat untuk platform tersebut.
// ─────────────────────────────────────────────────────────────────────────────

import { createNextGuardMiddleware, withNextGuard, withNextGuardPages, AppRouteHandler } from './middleware/nextjs.js';
import { nextGuardExpress, ExpressRequest, ExpressResponse, ExpressNextFunction } from './middleware/express.js';

export type Platform = 'next-middleware' | 'next-app' | 'next-pages' | 'express' | 'node';

/**
 * Universal guard adapter.
 * Mengembalikan middleware/wrapper yang sesuai dengan platform target.
 *
 * @example
 * // Next.js global middleware
 * export const middleware = applyGuard('next-middleware', loginSecurity);
 *
 * @example
 * // Next.js App Router handler
 * export const POST = applyGuard('next-app', loginSecurity)(handler);
 *
 * @example
 * // Express middleware
 * app.post('/login', applyGuard('express', loginSecurity), handler);
 */
export function applyGuard(platform: 'next-middleware', config: SecurityDefinition): ReturnType<typeof createNextGuardMiddleware>;
export function applyGuard(platform: 'next-app', config: SecurityDefinition): (handler: AppRouteHandler) => AppRouteHandler;
export function applyGuard(platform: 'next-pages', config: SecurityDefinition): (handler: Function) => Function;
export function applyGuard(platform: 'express' | 'node', config: SecurityDefinition): (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => Promise<void>;
export function applyGuard(platform: Platform, config: SecurityDefinition): unknown {
  switch (platform) {
    case 'next-middleware':
      return createNextGuardMiddleware(config);

    case 'next-app':
      return (handler: AppRouteHandler) => withNextGuard(handler, config);

    case 'next-pages':
      return (handler: Function) => withNextGuardPages(handler as any, config);

    case 'express':
    case 'node':
      return nextGuardExpress(config);

    default:
      throw new Error(`[NextGuard] Unknown platform: "${platform}". Use: 'next-middleware' | 'next-app' | 'next-pages' | 'express'`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: withGuard()
//
// Shorthand untuk Next.js App Router — paling sering dipakai.
// Sama dengan withNextGuard() tapi menerima SecurityDefinition.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Shorthand: lindungi App Router handler dengan SecurityDefinition.
 *
 * @example
 * import loginSecurity from '@/security/login';
 * export const POST = withGuard(handler, loginSecurity);
 */
export function withGuard(
  handler: AppRouteHandler,
  ...configs: SecurityDefinition[]
): AppRouteHandler {
  const merged = configs.length === 1 ? configs[0] : mergeGuard(...configs);
  return withNextGuard(handler, merged);
}

/**
 * Shorthand: lindungi Express route handler dengan SecurityDefinition.
 *
 * @example
 * import loginSecurity from '@/security/login';
 * app.post('/login', guardExpress(loginSecurity), handler);
 */
export function guardExpress(...configs: SecurityDefinition[]) {
  const merged = configs.length === 1 ? configs[0] : mergeGuard(...configs);
  return nextGuardExpress(merged);
}
