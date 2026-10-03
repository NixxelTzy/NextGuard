/**
 * NextGuard - In-Memory Sliding Window Store
 * High-performance, zero-dependency store with automated garbage collection.
 */
import { RateLimitStore, RateLimitEntry } from '../../types.js';
export declare class MemoryStore implements RateLimitStore {
    private map;
    private gcInterval;
    constructor(gcIntervalMs?: number);
    increment(key: string, windowMs: number): Promise<{
        count: number;
        resetTime: number;
    }>;
    get(key: string): Promise<RateLimitEntry | null>;
    jail(key: string, durationMs: number): Promise<void>;
    isJailed(key: string): Promise<boolean>;
    reset(key: string): Promise<void>;
    cleanup(): void;
    destroy(): void;
}
//# sourceMappingURL=memory-store.d.ts.map