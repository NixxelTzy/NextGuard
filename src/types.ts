/**
 * NextGuard - Web Application Firewall (WAF) Type Definitions
 */

export type ThreatType =
  | 'sql_injection'
  | 'xss'
  | 'command_injection'
  | 'path_traversal'
  | 'rate_limit_exceeded'
  | 'bad_bot'
  | 'ip_blacklisted'
  | 'payload_too_large'
  | 'suspicious_header'
  | 'custom_rule_violation';

export type FirewallMode = 'enforce' | 'monitor';

export type SensitivityLevel = 'low' | 'medium' | 'high';

export interface RequestContext {
  url: string;
  method: string;
  ip: string;
  headers: Record<string, string | string[] | undefined>;
  query?: Record<string, unknown>;
  body?: unknown;
  rawBody?: string;
}

export interface InspectionVerdict {
  allowed: boolean;
  threatType?: ThreatType;
  reason?: string;
  statusCode: number; // 200, 403, 429, 413, etc.
  clientIp: string;
  requestId: string;
  matchedPattern?: string;
  location?: 'query' | 'body' | 'header' | 'url' | 'ip';
  parameter?: string;
  timestamp: number;
  mode: FirewallMode;
}

export interface RateLimitEntry {
  count: number;
  resetTime: number;
  isJailed?: boolean;
  jailUntil?: number;
}

export interface RateLimitStore {
  increment(key: string, windowMs: number): Promise<{ count: number; resetTime: number }>;
  get(key: string): Promise<RateLimitEntry | null>;
  jail(key: string, durationMs: number): Promise<void>;
  isJailed(key: string): Promise<boolean>;
  reset?(key: string): Promise<void>;
}

export interface RateLimitConfig {
  enabled?: boolean;
  windowMs?: number; // e.g. 60000 (1 minute)
  max?: number; // max requests within windowMs
  jailDurationMs?: number; // if exceeded excessively or repeatedly, jail the IP
  jailThreshold?: number; // requests count that triggers automatic jail (default: max * 2)
  statusCode?: number; // default 429
  headers?: boolean; // include X-RateLimit-* headers
  keyGenerator?: (req: RequestContext) => string;
  store?: RateLimitStore;
}

export interface SQLiConfig {
  enabled?: boolean;
  inspectQuery?: boolean;
  inspectBody?: boolean;
  inspectHeaders?: boolean;
  inspectUrl?: boolean;
  sensitivity?: SensitivityLevel;
  customPatterns?: RegExp[];
  excludePatterns?: RegExp[];
}

export interface XSSConfig {
  enabled?: boolean;
  inspectQuery?: boolean;
  inspectBody?: boolean;
  inspectHeaders?: boolean;
  sensitivity?: SensitivityLevel;
  customPatterns?: RegExp[];
  excludePatterns?: RegExp[];
}

export interface CommandInjectionConfig {
  enabled?: boolean;
  inspectQuery?: boolean;
  inspectBody?: boolean;
  inspectHeaders?: boolean;
  customPatterns?: RegExp[];
}

export interface PathTraversalConfig {
  enabled?: boolean;
  inspectQuery?: boolean;
  inspectUrl?: boolean;
  inspectBody?: boolean;
  customPatterns?: RegExp[];
}

export interface BotConfig {
  enabled?: boolean;
  blockEmptyUserAgent?: boolean;
  knownScanners?: boolean; // sqlmap, nikto, acunetix, dirbuster, nmap, etc.
  customBlacklist?: (string | RegExp)[];
  whitelist?: (string | RegExp)[];
}

export interface IPFilterConfig {
  whitelist?: string[]; // Supports IPv4, IPv6 and CIDR (e.g. 192.168.1.0/24)
  blacklist?: string[];
  trustProxy?: boolean;
  customIpHeader?: string; // e.g. 'x-real-ip', 'cf-connecting-ip'
}

export interface PayloadGuardConfig {
  enabled?: boolean;
  maxBodySize?: number; // bytes (e.g. 5 * 1024 * 1024 = 5MB)
  inspectBody?: boolean;
}

export interface SecurityHeadersConfig {
  enabled?: boolean;
  contentSecurityPolicy?: string | false;
  xFrameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  xContentTypeOptions?: boolean;
  xXSSProtection?: '0' | '1; mode=block' | false;
  strictTransportSecurity?: string | false; // e.g. 'max-age=31536000; includeSubDomains'
  referrerPolicy?: string | false;
  permissionsPolicy?: string | false;
}

export interface CustomRule {
  name: string;
  description?: string;
  evaluate: (req: RequestContext) => boolean | Promise<boolean>;
  action?: 'block' | 'monitor';
  statusCode?: number;
  reason?: string;
}

export interface EndpointRuleOverride {
  rateLimit?: RateLimitConfig | false;
  sqlInjection?: SQLiConfig | boolean;
  xss?: XSSConfig | boolean;
  commandInjection?: CommandInjectionConfig | boolean;
  pathTraversal?: PathTraversalConfig | boolean;
  badBots?: BotConfig | boolean;
  payloadGuard?: PayloadGuardConfig | boolean;
}

export interface NextGuardConfig {
  mode?: FirewallMode; // 'enforce' (default) or 'monitor'
  rateLimit?: RateLimitConfig | false;
  sqlInjection?: SQLiConfig | boolean;
  xss?: XSSConfig | boolean;
  commandInjection?: CommandInjectionConfig | boolean;
  pathTraversal?: PathTraversalConfig | boolean;
  badBots?: BotConfig | boolean;
  ipFilter?: IPFilterConfig;
  payloadGuard?: PayloadGuardConfig;
  securityHeaders?: SecurityHeadersConfig | boolean;
  endpoints?: Record<string, EndpointRuleOverride>; // Route-specific rule overrides (e.g. '/api/login')
  excludePaths?: (string | RegExp)[]; // e.g. ['/_next/*', '/favicon.ico']
  customRules?: CustomRule[];
  onBlocked?: (verdict: InspectionVerdict, req: RequestContext) => void | Promise<void>;
  onAllowed?: (verdict: InspectionVerdict, req: RequestContext) => void | Promise<void>;
  htmlResponse?: boolean; // Render Cloudflare-like HTML page for browser requests
}
