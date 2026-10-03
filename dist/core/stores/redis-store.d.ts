/**
 * NextGuard - Redis Store Adapter
 * Enables distributed rate limiting and DoS synchronization across serverless/multi-cluster instances.
 */
import { RateLimitStore, RateLimitEntry } from '../../types.js';
export interface GenericRedisClient {
    incr(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<unknown>;
    ttl(key: string): Promise<number>;
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ...args: unknown[]): Promise<unknown>;
    del(key: string): Promise<unknown>;
}
export interface RedisStoreOptions {
    client: GenericRedisClient;
    prefix?: string;
}
export declare class RedisStore implements RateLimitStore {
    private client;
    private prefix;
    constructor(options: RedisStoreOptions);
    private getKey;
    private getJailKey;
    increment(key: string, windowMs: number): Promise<{
        count: number;
        resetTime: number;
    }>;
    get(key: string): Promise<RateLimitEntry | null>;
    jail(key: string, durationMs: number): Promise<void>;
    isJailed(key: string): Promise<boolean>;
    reset(key: string): Promise<void>;
}
//# sourceMappingURL=redis-store.d.ts.map