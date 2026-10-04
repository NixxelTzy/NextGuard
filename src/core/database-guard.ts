/**
 * NextGuard - Database Guard
 *
 * Modul perlindungan database per-endpoint. Pasang di file route yang
 * berinteraksi dengan database untuk mencegah:
 *   - Database flooding (write/read berlebihan)
 *   - Payload raksasa yang mengisi storage database
 *   - Bulk insertion spam
 *   - Data scraping / bulk extraction
 *   - Schema flooding (terlalu banyak field berbeda)
 *   - Deeply nested payload attacks
 *   - Duplicate write spam
 *
 * @example Next.js App Router
 * ```ts
 * // app/api/users/route.ts
 * import { createDatabaseGuard } from '@nixxeltzy/nextguard-next';
 *
 * const dbGuard = createDatabaseGuard({
 *   maxWritesPerMinute: 10,
 *   maxPayloadSizeBytes: 10_240, // 10KB
 * });
 *
 * export async function POST(req: Request) {
 *   const blocked = await dbGuard.protectNext(req);
 *   if (blocked) return blocked;
 *   // ... DB operation
 * }
 * ```
 *
 * @example Express / Node.js
 * ```ts
 * // routes/users.ts
 * import { createDatabaseGuard } from '@nixxeltzy/nextguard-node';
 *
 * const dbGuard = createDatabaseGuard({ maxWritesPerMinute: 10 });
 *
 * router.post('/api/users', dbGuard.middleware(), handler);
 * ```
 */

export interface DatabaseGuardConfig {
  /**
   * Max write operations (POST/PUT/PATCH/DELETE) per IP per minute.
   * Default: 20
   */
  maxWritesPerMinute?: number;

  /**
   * Max read operations (GET) per IP per minute.
   * Default: 100
   */
  maxReadsPerMinute?: number;

  /**
   * Max body payload size in bytes.
   * Prevents oversized data from filling database storage.
   * Default: 102400 (100KB)
   */
  maxPayloadSizeBytes?: number;

  /**
   * Max number of unique top-level fields in request body.
   * Prevents schema flooding attacks.
   * Default: 50
   */
  maxFieldCount?: number;

  /**
   * Max items in any array within the payload.
   * Prevents bulk insert spam.
   * Default: 500
   */
  maxArrayLength?: number;

  /**
   * Max JSON nesting depth.
   * Prevents deeply nested payload attacks.
   * Default: 8
   */
  maxNestingDepth?: number;

  /**
   * Prevent identical payloads from same IP within the window.
   * Prevents duplicate write spam.
   * Default: true
   */
  preventDuplicateWrites?: boolean;

  /**
   * Time window in ms for duplicate detection.
   * Default: 5000 (5 seconds)
   */
  duplicateWindowMs?: number;

  /**
   * Detect and block rapid sequential GET requests (data scraping).
   * Default: true
   */
  preventBulkExtraction?: boolean;

  /**
   * HTTP status code returned when blocked.
   * Default: 429
   */
  statusCode?: number;

  /**
   * Custom error message.
   */
  message?: string;
}

export interface DatabaseGuardResult {
  allowed: boolean;
  reason: string;
  statusCode: number;
  retryAfter?: number;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

interface RateWindow {
  count: number;
  resetAt: number;
}

function getJsonDepth(value: unknown, depth = 0): number {
  if (depth > 20) return depth; // early exit
  if (typeof value !== 'object' || value === null) return depth;
  if (Array.isArray(value)) {
    return Math.max(...(value as unknown[]).map(v => getJsonDepth(v, depth + 1)), depth + 1);
  }
  const vals = Object.values(value as Record<string, unknown>);
  if (vals.length === 0) return depth + 1;
  return Math.max(...vals.map(v => getJsonDepth(v, depth + 1)), depth + 1);
}

function getMaxArrayLength(value: unknown): number {
  if (typeof value !== 'object' || value === null) return 0;
  if (Array.isArray(value)) {
    return Math.max(
      value.length,
      ...(value as unknown[]).map(getMaxArrayLength)
    );
  }
  return Math.max(...Object.values(value as Record<string, unknown>).map(getMaxArrayLength), 0);
}

function simpleHash(str: string): string {
  let h = 0;
  for (let i = 0; i < Math.min(str.length, 512); i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return h.toString(36);
}

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// ── DatabaseGuard class ───────────────────────────────────────────────────────

export class DatabaseGuard {
  private maxWritesPerMin: number;
  private maxReadsPerMin: number;
  private maxPayloadSizeBytes: number;
  private maxFieldCount: number;
  private maxArrayLength: number;
  private maxNestingDepth: number;
  private preventDuplicates: boolean;
  private duplicateWindowMs: number;
  private preventBulkExtraction: boolean;
  private defaultStatusCode: number;
  private defaultMessage: string;

  // In-memory rate windows per IP
  private writeWindows = new Map<string, RateWindow>();
  private readWindows = new Map<string, RateWindow>();

  // Duplicate detection: hash → { ip, expiresAt }
  private recentHashes = new Map<string, { ip: string; expiresAt: number }>();

  constructor(config: DatabaseGuardConfig = {}) {
    this.maxWritesPerMin = config.maxWritesPerMinute ?? 20;
    this.maxReadsPerMin = config.maxReadsPerMinute ?? 100;
    this.maxPayloadSizeBytes = config.maxPayloadSizeBytes ?? 102_400; // 100KB
    this.maxFieldCount = config.maxFieldCount ?? 50;
    this.maxArrayLength = config.maxArrayLength ?? 500;
    this.maxNestingDepth = config.maxNestingDepth ?? 8;
    this.preventDuplicates = config.preventDuplicateWrites ?? true;
    this.duplicateWindowMs = config.duplicateWindowMs ?? 5_000;
    this.preventBulkExtraction = config.preventBulkExtraction ?? true;
    this.defaultStatusCode = config.statusCode ?? 429;
    this.defaultMessage = config.message ?? 'Database operation rate limit exceeded';
  }

  /**
   * Core inspection logic. Returns a DatabaseGuardResult.
   * Use protectNext() or middleware() for framework-specific integration.
   */
  public async inspect(
    ip: string,
    method: string,
    body?: unknown,
    bodyRaw?: string
  ): Promise<DatabaseGuardResult> {
    const now = Date.now();
    const upperMethod = method.toUpperCase();
    const isWrite = WRITE_METHODS.has(upperMethod);

    // ── 1. Write Rate Limit ────────────────────────────────────────────────
    if (isWrite) {
      const blocked = this.checkRateWindow(this.writeWindows, ip, this.maxWritesPerMin, 60_000, now);
      if (blocked) {
        return {
          allowed: false,
          reason: `Database write rate limit exceeded: max ${this.maxWritesPerMin} writes/min per IP`,
          statusCode: 429,
          retryAfter: Math.ceil((blocked.resetAt - now) / 1000),
        };
      }
    }

    // ── 2. Read Rate Limit (bulk extraction prevention) ───────────────────
    if (!isWrite && this.preventBulkExtraction) {
      const blocked = this.checkRateWindow(this.readWindows, ip, this.maxReadsPerMin, 60_000, now);
      if (blocked) {
        return {
          allowed: false,
          reason: `Database read rate limit exceeded: max ${this.maxReadsPerMin} reads/min per IP. Possible data scraping.`,
          statusCode: 429,
          retryAfter: Math.ceil((blocked.resetAt - now) / 1000),
        };
      }
    }

    // ── 3. Payload Inspection (only for write operations with body) ────────
    if (isWrite && body !== undefined && body !== null) {
      // 3a. Payload size
      const rawSize = bodyRaw ? bodyRaw.length : JSON.stringify(body).length;
      if (rawSize > this.maxPayloadSizeBytes) {
        return {
          allowed: false,
          reason: `Payload too large: ${rawSize} bytes exceeds database guard limit of ${this.maxPayloadSizeBytes} bytes. This could fill database storage.`,
          statusCode: 413,
        };
      }

      // 3b. Field count (top-level)
      if (typeof body === 'object' && !Array.isArray(body)) {
        const fieldCount = Object.keys(body as Record<string, unknown>).length;
        if (fieldCount > this.maxFieldCount) {
          return {
            allowed: false,
            reason: `Too many fields in payload: ${fieldCount} exceeds max ${this.maxFieldCount}. Possible schema flooding attack.`,
            statusCode: 400,
          };
        }
      }

      // 3c. Array length (bulk insert detection)
      const maxArr = getMaxArrayLength(body);
      if (maxArr > this.maxArrayLength) {
        return {
          allowed: false,
          reason: `Bulk insert detected: array contains ${maxArr} items, max allowed is ${this.maxArrayLength}. Use paginated writes instead.`,
          statusCode: 400,
        };
      }

      // 3d. Nesting depth
      const depth = getJsonDepth(body);
      if (depth > this.maxNestingDepth) {
        return {
          allowed: false,
          reason: `Payload nesting depth ${depth} exceeds max ${this.maxNestingDepth}. Possible deeply nested payload attack.`,
          statusCode: 400,
        };
      }

      // 3e. Duplicate write detection
      if (this.preventDuplicates && bodyRaw) {
        this.cleanExpiredHashes(now);
        const hash = simpleHash(ip + bodyRaw);
        const existing = this.recentHashes.get(hash);
        if (existing && existing.ip === ip && existing.expiresAt > now) {
          return {
            allowed: false,
            reason: `Duplicate write detected: identical payload submitted within ${this.duplicateWindowMs}ms. Possible write spam.`,
            statusCode: 429,
            retryAfter: Math.ceil((existing.expiresAt - now) / 1000),
          };
        }
        this.recentHashes.set(hash, { ip, expiresAt: now + this.duplicateWindowMs });
      }
    }

    return { allowed: true, reason: 'Allowed', statusCode: 200 };
  }

  /**
   * Protect a Next.js App Router route handler.
   * Returns a blocked Response if the request should be blocked, or undefined to allow.
   *
   * @example
   * export async function POST(req: Request) {
   *   const blocked = await dbGuard.protectNext(req);
   *   if (blocked) return blocked;
   *   // ...
   * }
   */
  public async protectNext(req: Request): Promise<Response | undefined> {
    const ip = this.extractIp(req.headers);
    const method = req.method;
    let body: unknown;
    let bodyRaw: string | undefined;

    // Only parse body for write operations
    if (WRITE_METHODS.has(method.toUpperCase())) {
      try {
        bodyRaw = await req.clone().text();
        body = bodyRaw ? JSON.parse(bodyRaw) : undefined;
      } catch {
        body = undefined;
      }
    }

    const result = await this.inspect(ip, method, body, bodyRaw);
    if (result.allowed) return undefined;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-NextGuard-Database-Protection': 'blocked',
    };
    if (result.retryAfter) {
      headers['Retry-After'] = String(result.retryAfter);
    }

    return new Response(
      JSON.stringify({
        error: 'Database Protection',
        message: result.reason,
        statusCode: result.statusCode,
        retryAfter: result.retryAfter,
      }),
      { status: result.statusCode, headers }
    );
  }

  /**
   * Express/Node.js middleware factory.
   * Use as: router.post('/api/data', dbGuard.middleware(), handler)
   */
  public middleware() {
    return async (req: any, res: any, next: any) => {
      const ip: string =
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.headers['cf-connecting-ip'] ||
        req.socket?.remoteAddress ||
        req.ip ||
        '0.0.0.0';

      const method: string = req.method || 'GET';
      const body = req.body;
      const bodyRaw = typeof body === 'string' ? body : body ? JSON.stringify(body) : undefined;

      const result = await this.inspect(ip, method, body, bodyRaw);

      if (!result.allowed) {
        res.set('X-NextGuard-Database-Protection', 'blocked');
        if (result.retryAfter) {
          res.set('Retry-After', String(result.retryAfter));
        }
        return res.status(result.statusCode).json({
          error: 'Database Protection',
          message: result.reason,
          statusCode: result.statusCode,
          retryAfter: result.retryAfter,
        });
      }

      next();
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private checkRateWindow(
    windows: Map<string, RateWindow>,
    ip: string,
    max: number,
    windowMs: number,
    now: number
  ): RateWindow | null {
    let win = windows.get(ip);
    if (!win || win.resetAt <= now) {
      win = { count: 1, resetAt: now + windowMs };
      windows.set(ip, win);
      return null;
    }
    win.count++;
    if (win.count > max) return win;
    return null;
  }

  private cleanExpiredHashes(now: number): void {
    if (this.recentHashes.size < 1000) return;
    for (const [k, v] of this.recentHashes) {
      if (v.expiresAt <= now) this.recentHashes.delete(k);
    }
  }

  private extractIp(headers: Headers): string {
    return (
      headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      headers.get('cf-connecting-ip') ||
      headers.get('x-real-ip') ||
      headers.get('x-vercel-forwarded-for') ||
      '0.0.0.0'
    );
  }

  /** Reset all rate windows and caches (useful for testing) */
  public reset(): void {
    this.writeWindows.clear();
    this.readWindows.clear();
    this.recentHashes.clear();
  }
}

/**
 * Buat instance DatabaseGuard baru.
 * Import dan gunakan di file route yang berinteraksi dengan database.
 *
 * @example Next.js
 * ```ts
 * import { createDatabaseGuard } from '@nixxeltzy/nextguard-next';
 *
 * const dbGuard = createDatabaseGuard({
 *   maxWritesPerMinute: 10,
 *   maxPayloadSizeBytes: 51_200, // 50KB
 *   preventDuplicateWrites: true,
 * });
 *
 * // app/api/users/route.ts
 * export async function POST(req: Request) {
 *   const blocked = await dbGuard.protectNext(req);
 *   if (blocked) return blocked;
 *   // aman, lanjut ke DB
 * }
 * ```
 */
export function createDatabaseGuard(config: DatabaseGuardConfig = {}): DatabaseGuard {
  return new DatabaseGuard(config);
}
