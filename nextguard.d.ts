// Type definitions for NextGuard v1.0.0

import { EventEmitter } from 'events';
import { IncomingMessage, ServerResponse } from 'http';

export declare const VERSION: string;

// ─── Configuration Types ────────────────────────────────────────────────────

export interface Layer1Config {
  enabled?: boolean;
  /** Array of IP addresses or CIDR ranges to permanently block */
  staticBlacklist?: string[];
  /** Auto-ban an IP after this many violations */
  autobanOnViolations?: number;
  /** Duration of auto-ban in milliseconds (default: 1 hour) */
  banDurationMs?: number;
}

export interface Layer2Config {
  enabled?: boolean;
  /** Time window for rate limiting in ms (default: 60000) */
  windowMs?: number;
  /** Max requests per window per IP (default: 120) */
  maxRequests?: number;
  /** Max requests per burst window (default: 30) */
  burstLimit?: number;
  /** Burst window in ms (default: 5000) */
  burstWindowMs?: number;
  /** Penalty/cool-down duration in ms (default: 30000) */
  penaltyMs?: number;
}

export interface Layer3Config {
  enabled?: boolean;
  /** Max unique paths an IP may request per window (default: 40) */
  maxPathsPerWindow?: number;
  /** Max error responses per window before flagging (default: 15) */
  maxErrorsPerWindow?: number;
  /** Cookie name for browser fingerprint (default: '__ng_fp') */
  fingerprintCookieName?: string;
  /** Enable JavaScript proof-of-work challenge for suspicious IPs (default: false) */
  jsChallenge?: boolean;
}

export interface Layer4Config {
  enabled?: boolean;
  /** Block requests missing a User-Agent header (default: true) */
  requireUserAgent?: boolean;
  /** Block known malicious user agents (scanners, bots, exploit tools) (default: true) */
  blockMaliciousUA?: boolean;
  /** Block HTTPS connections without SNI (default: false) */
  blockMissingSNI?: boolean;
  /** Maximum allowed header size in bytes (default: 8192) */
  maxHeaderSize?: number;
}

export interface Layer5Config {
  enabled?: boolean;
  /** Maximum body size in bytes (default: 2097152 = 2MB) */
  maxBodySize?: number;
  /** Inspect query string parameters for attack payloads (default: true) */
  inspectQuery?: boolean;
  /** Inspect request body for attack payloads (default: true) */
  inspectBody?: boolean;
  /** Inspect cookies for attack payloads (default: true) */
  inspectCookies?: boolean;
  /** Inspect request headers for attack payloads (default: true) */
  inspectHeaders?: boolean;
}

export interface Layer6Config {
  enabled?: boolean;
  /**
   * If non-empty, ONLY allow requests from these ISO 3166-1 alpha-2 country codes.
   * e.g. ['US', 'ID', 'SG']
   */
  allowedCountries?: string[];
  /**
   * Always block these ISO 3166-1 alpha-2 country codes.
   * e.g. ['CN', 'RU', 'KP']
   */
  blockedCountries?: string[];
  /**
   * URL template for geo lookup API.
   * Use {ip} as placeholder. Response must include `countryCode` field.
   * e.g. 'http://ip-api.com/json/{ip}?fields=countryCode'
   */
  geoApiUrl?: string | null;
}

export interface Layer7Config {
  enabled?: boolean;
  /** Enable tarpit — hold attacker connections open to waste their resources */
  tarpitEnabled?: boolean;
  /** How long to tarpit a connection in ms (default: 10000) */
  tarpitDelayMs?: number;
  /** Maximum tarpit duration per session in ms (default: 60000) */
  tarpitMaxMs?: number;
  /** Enable slow-read — send data byte-by-byte to drain attacker buffers */
  slowReadEnabled?: boolean;
  /** Interval between slow-read chunks in ms (default: 2000) */
  slowReadChunkMs?: number;
  /** Enable reset storm — flood attacker with garbage to crash scanner state */
  resetStormEnabled?: boolean;
  /**
   * URL paths that act as honeypots — any access triggers tarpit and violation recording.
   * Defaults include: /.env, /wp-admin, /admin, /phpmyadmin, /.git/HEAD, etc.
   */
  honeypotPaths?: string[];
}

export interface NextGuardConfig {
  /** Instance name for logging (default: 'NextGuard') */
  name?: string;
  /**
   * Operating mode:
   * - 'protect' (default): Actively block and counter threats
   * - 'monitor': Log threats but allow all traffic
   * - 'lockdown': Block ALL traffic (emergency mode)
   */
  mode?: 'protect' | 'monitor' | 'lockdown';
  /** Trust X-Forwarded-For and similar proxy headers for IP detection (default: true) */
  trustProxy?: boolean;
  /** Log verbosity: 'silent' | 'warn' | 'info' | 'debug' (default: 'warn') */
  logLevel?: 'silent' | 'warn' | 'info' | 'debug';
  layer1?: Layer1Config;
  layer2?: Layer2Config;
  layer3?: Layer3Config;
  layer4?: Layer4Config;
  layer5?: Layer5Config;
  layer6?: Layer6Config;
  layer7?: Layer7Config;
}

// ─── Result Types ───────────────────────────────────────────────────────────

export interface GuardResult {
  blocked: boolean;
  layer?: number;
  reason?: string;
  handled?: boolean;
}

export interface Stats {
  version: string;
  uptime: number;
  mode: string;
  trackedIPs: number;
  bannedIPs: number;
  tarpittedIPs: number;
  challenges: number;
  topOffenders: Array<{ ip: string; violations: number; requests: number }>;
}

export interface ThreatEvent {
  ip: string;
  layer: number;
  reason: string;
  req: IncomingMessage | Request;
}

// ─── NextGuard Instance ──────────────────────────────────────────────────────

export interface NextGuardInstance {
  /**
   * Express-compatible middleware.
   * @example
   * import express from 'express';
   * import { createNextGuard } from 'nextguard';
   * const app = express();
   * const guard = createNextGuard();
   * app.use(guard.middleware);
   */
  middleware: (req: IncomingMessage, res: ServerResponse, next: (err?: Error) => void) => void;

  /**
   * Next.js App Router middleware.
   * Use this in your `middleware.ts` at the project root.
   * @example
   * // middleware.ts
   * import { createNextGuard } from 'nextguard';
   * const guard = createNextGuard();
   * export const middleware = guard.nextMiddleware;
   * export const config = { matcher: ['/((?!_next/static|favicon.ico).*)'] };
   */
  nextMiddleware: (req: Request) => Promise<Response | null>;

  /**
   * Wrap a raw Node.js HTTP handler.
   * @example
   * import http from 'http';
   * import { createNextGuard } from 'nextguard';
   * const guard = createNextGuard();
   * const server = http.createServer(guard.handler(myHandler));
   */
  handler: (next: (req: IncomingMessage, res: ServerResponse) => void) => (req: IncomingMessage, res: ServerResponse) => void;

  /** Manually ban an IP address */
  ban: (ip: string, options?: { durationMs?: number; reason?: string }) => void;

  /** Remove a ban from an IP address */
  unban: (ip: string) => void;

  /** Get current shield statistics */
  getStats: () => Stats;

  /** Switch operating mode at runtime */
  setMode: (mode: 'protect' | 'monitor' | 'lockdown') => void;

  /** Add an IP or CIDR to the runtime blacklist */
  addToBlacklist: (ip: string) => void;

  /** Remove an IP or CIDR from the runtime blacklist */
  removeFromBlacklist: (ip: string) => void;

  /** EventEmitter for threat events */
  events: EventEmitter;

  /** Resolved configuration */
  config: Required<NextGuardConfig>;

  /** Package version */
  version: string;
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Create a NextGuard firewall instance with custom configuration.
 *
 * @example
 * import { createNextGuard } from 'nextguard';
 *
 * const guard = createNextGuard({
 *   logLevel: 'info',
 *   layer2: { maxRequests: 60, windowMs: 60_000 },
 *   layer6: { enabled: true, blockedCountries: ['CN', 'RU'] },
 *   layer7: { tarpitEnabled: true, tarpitDelayMs: 30_000 },
 * });
 *
 * guard.events.on('threat', ({ ip, layer, reason }) => {
 *   console.log(`Threat from ${ip} at layer ${layer}: ${reason}`);
 * });
 */
export declare function createNextGuard(config?: NextGuardConfig): NextGuardInstance;

// ─── Utility Exports ─────────────────────────────────────────────────────────

/** Extract the real client IP from a request (respects X-Forwarded-For, CF-Connecting-IP, etc.) */
export declare function getClientIP(req: IncomingMessage | Request, trustProxy?: boolean): string;

/** Inspect a single string value for known attack signatures */
export declare function inspectValue(value: string): { matched: boolean; pattern: string | null };

/** Deep-inspect an object (query params, body) for attack patterns */
export declare function deepInspect(obj: unknown, path?: string): { matched: boolean; pattern: string | null; path: string | null };

/** Check if an IP address falls within a CIDR range */
export declare function ipInCIDR(ip: string, cidr: string): boolean;

// ─── Default Instance Exports ────────────────────────────────────────────────

/** Default instance middleware (zero-config) */
export declare const middleware: NextGuardInstance['middleware'];

/** Default instance Next.js middleware (zero-config) */
export declare const nextMiddleware: NextGuardInstance['nextMiddleware'];

/** Default instance raw handler wrapper (zero-config) */
export declare const handler: NextGuardInstance['handler'];

/** Ban an IP on the default instance */
export declare const ban: NextGuardInstance['ban'];

/** Unban an IP on the default instance */
export declare const unban: NextGuardInstance['unban'];

/** Get stats from the default instance */
export declare const getStats: NextGuardInstance['getStats'];

/** Set mode on the default instance */
export declare const setMode: NextGuardInstance['setMode'];

/** Events from the default instance */
export declare const events: NextGuardInstance['events'];

/** Package version string */
export declare const VERSION: string;
