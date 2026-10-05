// Type definitions for NextGuard v1.1.0

import { EventEmitter } from 'events';
import { IncomingMessage, ServerResponse } from 'http';

export declare const VERSION: string;

// ─── Configuration Types ────────────────────────────────────────────────────

export interface TelegramConfig {
  /** Enable Telegram alert notifications (default: false, or auto-true if botToken and chatId are set) */
  enabled?: boolean;
  /** Telegram bot token from @BotFather (or read from process.env.TELEGRAM_BOT_TOKEN) */
  botToken?: string | null;
  /** Telegram chat ID to receive alerts (or read from process.env.TELEGRAM_CHAT_ID) */
  chatId?: string | null;
  /** Debounce cooldown in ms per IP+Layer to prevent alert floods during DDoS (default: 30000) */
  cooldownMs?: number;
  /** Minimum firewall layer to trigger a Telegram alert: 1-7 (default: 1) */
  minLayer?: number;
}

export interface AdminConfig {
  /** Enable internal admin endpoints like /stats, /ban, /unban (default: false) */
  enabled?: boolean;
  /** Route prefix for admin endpoints if enabled (default: '/__nextguard') */
  routePrefix?: string;
}

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
  /** If non-empty, ONLY allow requests from these ISO 3166-1 alpha-2 country codes */
  allowedCountries?: string[];
  /** Always block these ISO 3166-1 alpha-2 country codes */
  blockedCountries?: string[];
  /** URL template for geo lookup API, e.g. 'http://ip-api.com/json/{ip}?fields=countryCode' */
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
  /** Honeypot exploit probes — only pure probe paths like /.env, /.git/HEAD */
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
  /** Real-time Telegram security alerts (optimized for Vercel) */
  telegram?: TelegramConfig;
  /** Optional admin routes (default: disabled) */
  admin?: AdminConfig;
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
  path: string;
  method: string;
  action: string;
  timestamp: string;
  req: IncomingMessage | Request;
}

// ─── Middleware Interface ────────────────────────────────────────────────────

export interface NextGuardMiddleware {
  /** Express / Node.js HTTP signature */
  (req: IncomingMessage, res: ServerResponse, next?: (err?: Error) => void): void;
  /** Next.js App Router / Edge middleware signature */
  (req: Request): Promise<Response | null>;

  instance: NextGuardInstance;
  middleware: (req: IncomingMessage, res: ServerResponse, next: (err?: Error) => void) => void;
  nextMiddleware: (req: Request) => Promise<Response | null>;
  handler: (next: (req: IncomingMessage, res: ServerResponse) => void) => (req: IncomingMessage, res: ServerResponse) => void;
  ban: (ip: string, options?: { durationMs?: number; reason?: string }) => void;
  unban: (ip: string) => void;
  getStats: () => Stats;
  setMode: (mode: 'protect' | 'monitor' | 'lockdown') => void;
  addToBlacklist: (ip: string) => void;
  removeFromBlacklist: (ip: string) => void;
  events: EventEmitter;
  config: Required<NextGuardConfig>;
  version: string;
}

// ─── NextGuard Instance ──────────────────────────────────────────────────────

export interface NextGuardInstance {
  middleware: (req: IncomingMessage, res: ServerResponse, next: (err?: Error) => void) => void;
  nextMiddleware: (req: Request) => Promise<Response | null>;
  universalMiddleware: NextGuardMiddleware;
  handler: (next: (req: IncomingMessage, res: ServerResponse) => void) => (req: IncomingMessage, res: ServerResponse) => void;
  ban: (ip: string, options?: { durationMs?: number; reason?: string }) => void;
  unban: (ip: string) => void;
  getStats: () => Stats;
  setMode: (mode: 'protect' | 'monitor' | 'lockdown') => void;
  addToBlacklist: (ip: string) => void;
  removeFromBlacklist: (ip: string) => void;
  sendTelegramAlert: (threatInfo: Partial<ThreatEvent>) => Promise<boolean>;
  events: EventEmitter;
  config: Required<NextGuardConfig>;
  version: string;
}

// ─── Callable Entry Point ────────────────────────────────────────────────────

export interface NextGuardCallable {
  /**
   * Usage 1: Create zero-config middleware for Next.js or Express:
   * @example
   * import { nextguard } from "nextguard";
   * export const middleware = nextguard();
   * export const config = { matcher: ["/:path*"] };
   */
  (): NextGuardMiddleware;

  /**
   * Usage 2: Create configured middleware:
   * @example
   * import { nextguard } from "nextguard";
   * export const middleware = nextguard({
   *   layer2: { maxRequests: 60 },
   *   telegram: { botToken: process.env.TELEGRAM_BOT_TOKEN, chatId: process.env.TELEGRAM_CHAT_ID }
   * });
   */
  (config: NextGuardConfig): NextGuardMiddleware;

  /**
   * Usage 3: Direct functional Next.js middleware:
   * @example
   * import { nextguard } from "nextguard";
   * export function middleware(request) {
   *   return nextguard(request);
   * }
   */
  (request: Request): Promise<Response | null>;
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export declare function createNextGuard(config?: NextGuardConfig): NextGuardInstance;

export declare function getClientIP(req: IncomingMessage | Request, trustProxy?: boolean): string;
export declare function inspectValue(value: string): { matched: boolean; pattern: string | null };
export declare function deepInspect(obj: unknown, path?: string): { matched: boolean; pattern: string | null; path: string | null };
export declare function ipInCIDR(ip: string, cidr: string): boolean;
export declare function sendTelegramAlert(threatInfo: Partial<ThreatEvent>, config?: NextGuardConfig): Promise<boolean>;

export declare const nextguard: NextGuardCallable & {
  nextguard: NextGuardCallable;
  createNextGuard: typeof createNextGuard;
  middleware: NextGuardMiddleware;
  nextMiddleware: (req: Request) => Promise<Response | null>;
  handler: NextGuardInstance['handler'];
  ban: NextGuardInstance['ban'];
  unban: NextGuardInstance['unban'];
  getStats: NextGuardInstance['getStats'];
  setMode: NextGuardInstance['setMode'];
  addToBlacklist: NextGuardInstance['addToBlacklist'];
  removeFromBlacklist: NextGuardInstance['removeFromBlacklist'];
  events: EventEmitter;
  sendTelegramAlert: typeof sendTelegramAlert;
  getClientIP: typeof getClientIP;
  inspectValue: typeof inspectValue;
  deepInspect: typeof deepInspect;
  ipInCIDR: typeof ipInCIDR;
  VERSION: string;
};

export default nextguard;
