import { EventEmitter } from 'events';
import { IncomingMessage, ServerResponse } from 'http';

export declare const VERSION: string;

export interface TelegramConfig {
  enabled?: boolean;
  botToken?: string | null;
  chatId?: string | null;
  cooldownMs?: number;
  minLayer?: number;
}

export interface AdminConfig {
  enabled?: boolean;
  routePrefix?: string;
}

export interface Layer1Config {
  enabled?: boolean;
  staticBlacklist?: string[];
  autobanOnViolations?: number;
  banDurationMs?: number;
}

export interface Layer2Config {
  enabled?: boolean;
  windowMs?: number;
  maxRequests?: number;
  burstLimit?: number;
  burstWindowMs?: number;
  penaltyMs?: number;
}

export interface Layer3Config {
  enabled?: boolean;
  maxPathsPerWindow?: number;
  maxErrorsPerWindow?: number;
  fingerprintCookieName?: string;
  jsChallenge?: boolean;
}

export interface Layer4Config {
  enabled?: boolean;
  requireUserAgent?: boolean;
  blockMaliciousUA?: boolean;
  blockMissingSNI?: boolean;
  maxHeaderSize?: number;
}

export interface Layer5Config {
  enabled?: boolean;
  maxBodySize?: number;
  inspectQuery?: boolean;
  inspectBody?: boolean;
  inspectCookies?: boolean;
  inspectHeaders?: boolean;
}

export interface Layer6Config {
  enabled?: boolean;
  allowedCountries?: string[];
  blockedCountries?: string[];
  geoApiUrl?: string | null;
}

export interface Layer7Config {
  enabled?: boolean;
  tarpitEnabled?: boolean;
  tarpitDelayMs?: number;
  tarpitMaxMs?: number;
  slowReadEnabled?: boolean;
  slowReadChunkMs?: number;
  resetStormEnabled?: boolean;
  honeypotPaths?: string[];
}

export interface NextGuardConfig {
  name?: string;
  mode?: 'protect' | 'monitor' | 'lockdown';
  trustProxy?: boolean;
  logLevel?: 'silent' | 'warn' | 'info' | 'debug';
  telegram?: TelegramConfig;
  admin?: AdminConfig;
  layer1?: Layer1Config;
  layer2?: Layer2Config;
  layer3?: Layer3Config;
  layer4?: Layer4Config;
  layer5?: Layer5Config;
  layer6?: Layer6Config;
  layer7?: Layer7Config;
}

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

export interface NextGuardMiddleware {
  (req: IncomingMessage, res: ServerResponse, next?: (err?: Error) => void): void;
  (req: Request): Promise<Response | null>;

  instance: NextGuardInstance;
  middleware: (req: IncomingMessage, res: ServerResponse, next?: (err?: Error) => void) => void;
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

export interface NextGuardInstance {
  middleware: (req: IncomingMessage, res: ServerResponse, next?: (err?: Error) => void) => void;
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

export interface NextGuardCallable {
  (): NextGuardMiddleware;
  (config: NextGuardConfig): NextGuardMiddleware;
  (request: Request): Promise<Response | null>;
}

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
