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
import { NextGuardConfig } from './types.js';
export interface SecurityDefinition extends NextGuardConfig {
    /** Nama identitas endpoint ini (opsional, untuk logging/debugging) */
    readonly $name?: string;
    /** Deskripsi singkat tujuan security config ini */
    readonly $description?: string;
    /** Tag kategori, misal: 'auth', 'payment', 'public' */
    readonly $tags?: string[];
}
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
export declare function defineEndpointSecurity(config: SecurityDefinition): SecurityDefinition;
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
export declare function mergeGuard(...configs: SecurityDefinition[]): SecurityDefinition;
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
export declare function createGuardGroup(base: SecurityDefinition): GuardGroup;
import { createNextGuardMiddleware, AppRouteHandler } from './middleware/nextjs.js';
import { ExpressRequest, ExpressResponse, ExpressNextFunction } from './middleware/express.js';
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
export declare function applyGuard(platform: 'next-middleware', config: SecurityDefinition): ReturnType<typeof createNextGuardMiddleware>;
export declare function applyGuard(platform: 'next-app', config: SecurityDefinition): (handler: AppRouteHandler) => AppRouteHandler;
export declare function applyGuard(platform: 'next-pages', config: SecurityDefinition): (handler: Function) => Function;
export declare function applyGuard(platform: 'express' | 'node', config: SecurityDefinition): (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => Promise<void>;
/**
 * Shorthand: lindungi App Router handler dengan SecurityDefinition.
 *
 * @example
 * import loginSecurity from '@/security/login';
 * export const POST = withGuard(handler, loginSecurity);
 */
export declare function withGuard(handler: AppRouteHandler, ...configs: SecurityDefinition[]): AppRouteHandler;
/**
 * Shorthand: lindungi Express route handler dengan SecurityDefinition.
 *
 * @example
 * import loginSecurity from '@/security/login';
 * app.post('/login', guardExpress(loginSecurity), handler);
 */
export declare function guardExpress(...configs: SecurityDefinition[]): (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => Promise<void>;
//# sourceMappingURL=define.d.ts.map