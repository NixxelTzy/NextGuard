/**
 * NextGuard - Rate Limiter & DoS Mitigation Engine
 * Features sliding-window counter and automatic IP jailing (Fail2ban style).
 */
import { RateLimitConfig, RateLimitStore, RequestContext } from '../types.js';
export interface RateLimitResult {
    allowed: boolean;
    limit: number;
    remaining: number;
    resetTime: number;
    retryAfterSec: number;
    isJailed: boolean;
    headers: Record<string, string>;
}
export declare class RateLimiter {
    private enabled;
    private windowMs;
    private max;
    private jailDurationMs;
    private jailThreshold;
    private store;
    private keyGenerator?;
    constructor(config?: RateLimitConfig);
    generateKey(req: RequestContext): string;
    check(req: RequestContext, overrideConfig?: RateLimitConfig): Promise<RateLimitResult>;
    jailKey(key: string, durationMs: number): Promise<void>;
    getStore(): RateLimitStore;
}
//# sourceMappingURL=rate-limiter.d.ts.map