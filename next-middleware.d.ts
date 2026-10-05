export interface RateLimitTier {
  max: number;
  windowMs: number;
}

export interface RateLimitConfig {
  page?: RateLimitTier;
  api?: RateLimitTier;
  auth?: RateLimitTier;
  heavy?: RateLimitTier;
  [key: string]: RateLimitTier | undefined;
}

export interface BruteForceConfig {
  enabled?: boolean;
  maxFails?: number;
  lockoutMs?: number;
  paths?: string[];
}

export interface MaxBodySizeConfig {
  page?: number;
  api?: number;
  heavy?: number;
}

export interface BlockContext {
  request: Request;
  ip: string;
  code: string;
  reason: string;
  layer: number | string;
  status: number;
}

export interface AllowContext {
  request: Request;
  ip: string;
  tier: string;
}

export interface MiddlewareOptions {
  guard?: import('./nextguard').NextGuardConfig;
  publicPaths?: string[];
  authCookie?: string;
  loginPath?: string;
  blockedPath?: string | null;
  apiPrefix?: string;
  authApiPaths?: string[];
  heavyApiPaths?: string[];
  skipAuth?: boolean;
  skipFirewall?: boolean;
  skipRateLimit?: boolean;
  ipHeaders?: string[];
  securityHeaders?: Record<string, string>;
  rateLimit?: RateLimitConfig;
  bruteForce?: BruteForceConfig;
  maxBodySize?: MaxBodySizeConfig;
  onBlock?: (ctx: BlockContext) => Promise<Response | void> | Response | void;
  onAllow?: (ctx: AllowContext) => Promise<Response | void> | Response | void;
}

export declare function createMiddleware(
  options?: MiddlewareOptions
): (request: Request) => Promise<Response | null>;
