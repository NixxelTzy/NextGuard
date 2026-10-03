/**
 * NextGuard - Rate Limiter & DoS Mitigation Engine
 * Features sliding-window counter and automatic IP jailing (Fail2ban style).
 */

import { RateLimitConfig, RateLimitStore, RequestContext } from '../types.js';
import { MemoryStore } from './stores/memory-store.js';

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetTime: number;
  retryAfterSec: number;
  isJailed: boolean;
  headers: Record<string, string>;
}

export class RateLimiter {
  private enabled: boolean;
  private windowMs: number;
  private max: number;
  private jailDurationMs: number;
  private jailThreshold: number;
  private store: RateLimitStore;
  private keyGenerator?: (req: RequestContext) => string;

  constructor(config?: RateLimitConfig) {
    this.enabled = config?.enabled ?? true;
    this.windowMs = config?.windowMs ?? 60000; // 1 minute default
    this.max = config?.max ?? 100; // 100 requests per minute
    this.jailDurationMs = config?.jailDurationMs ?? 300000; // 5 minute jail default
    this.jailThreshold = config?.jailThreshold ?? this.max * 2; // Auto-jail at 2x max
    this.store = config?.store ?? new MemoryStore();
    this.keyGenerator = config?.keyGenerator;
  }

  public generateKey(req: RequestContext): string {
    if (this.keyGenerator) {
      return this.keyGenerator(req);
    }
    // Default key: client IP + normalized path
    const urlPath = req.url.split('?')[0];
    return `${req.ip}:${urlPath}`;
  }

  public async check(req: RequestContext, overrideConfig?: RateLimitConfig): Promise<RateLimitResult> {
    const isEnabled = overrideConfig?.enabled ?? this.enabled;
    const windowMs = overrideConfig?.windowMs ?? this.windowMs;
    const max = overrideConfig?.max ?? this.max;
    const jailDuration = overrideConfig?.jailDurationMs ?? this.jailDurationMs;
    const jailThreshold = overrideConfig?.jailThreshold ?? this.jailThreshold;

    const defaultAllowedResult: RateLimitResult = {
      allowed: true,
      limit: max,
      remaining: max,
      resetTime: Date.now() + windowMs,
      retryAfterSec: 0,
      isJailed: false,
      headers: {},
    };

    if (!isEnabled) {
      return defaultAllowedResult;
    }

    const key = overrideConfig?.keyGenerator ? overrideConfig.keyGenerator(req) : this.generateKey(req);

    // 1. Check if the client is currently jailed
    const jailed = await this.store.isJailed(key);
    if (jailed) {
      const entry = await this.store.get(key);
      const remainingJailSec = entry?.jailUntil
        ? Math.max(1, Math.ceil((entry.jailUntil - Date.now()) / 1000))
        : Math.ceil(jailDuration / 1000);

      return {
        allowed: false,
        limit: max,
        remaining: 0,
        resetTime: entry?.jailUntil || Date.now() + jailDuration,
        retryAfterSec: remainingJailSec,
        isJailed: true,
        headers: {
          'X-RateLimit-Limit': String(max),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': String(Math.ceil((entry?.jailUntil || Date.now() + jailDuration) / 1000)),
          'Retry-After': String(remainingJailSec),
        },
      };
    }

    // 2. Increment request count
    const { count, resetTime } = await this.store.increment(key, windowMs);
    const retryAfterSec = Math.max(1, Math.ceil((resetTime - Date.now()) / 1000));
    const remaining = Math.max(0, max - count);

    const headers: Record<string, string> = {
      'X-RateLimit-Limit': String(max),
      'X-RateLimit-Remaining': String(remaining),
      'X-RateLimit-Reset': String(Math.ceil(resetTime / 1000)),
    };

    // 3. Check for DoS / brute-force volume exceeding jail threshold
    if (count >= jailThreshold) {
      await this.store.jail(key, jailDuration);
      headers['Retry-After'] = String(Math.ceil(jailDuration / 1000));
      return {
        allowed: false,
        limit: max,
        remaining: 0,
        resetTime: Date.now() + jailDuration,
        retryAfterSec: Math.ceil(jailDuration / 1000),
        isJailed: true,
        headers,
      };
    }

    // 4. Check if standard rate limit is exceeded
    if (count > max) {
      headers['Retry-After'] = String(retryAfterSec);
      return {
        allowed: false,
        limit: max,
        remaining: 0,
        resetTime,
        retryAfterSec,
        isJailed: false,
        headers,
      };
    }

    return {
      allowed: true,
      limit: max,
      remaining,
      resetTime,
      retryAfterSec: 0,
      isJailed: false,
      headers,
    };
  }
}
