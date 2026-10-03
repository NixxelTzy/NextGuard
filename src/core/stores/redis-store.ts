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

export class RedisStore implements RateLimitStore {
  private client: GenericRedisClient;
  private prefix: string;

  constructor(options: RedisStoreOptions) {
    this.client = options.client;
    this.prefix = options.prefix || 'nextguard:rl:';
  }

  private getKey(key: string): string {
    return `${this.prefix}${key}`;
  }

  private getJailKey(key: string): string {
    return `${this.prefix}jail:${key}`;
  }

  public async increment(key: string, windowMs: number): Promise<{ count: number; resetTime: number }> {
    const redisKey = this.getKey(key);
    const count = await this.client.incr(redisKey);

    if (count === 1) {
      const ttlSec = Math.ceil(windowMs / 1000);
      await this.client.expire(redisKey, ttlSec);
      return { count: 1, resetTime: Date.now() + windowMs };
    }

    const ttl = await this.client.ttl(redisKey);
    const resetTime = ttl > 0 ? Date.now() + ttl * 1000 : Date.now() + windowMs;
    return { count, resetTime };
  }

  public async get(key: string): Promise<RateLimitEntry | null> {
    const redisKey = this.getKey(key);
    const jailKey = this.getJailKey(key);

    const [val, ttl, jailVal] = await Promise.all([
      this.client.get(redisKey),
      this.client.ttl(redisKey),
      this.client.get(jailKey),
    ]);

    if (!val && !jailVal) return null;

    const count = val ? parseInt(val, 10) : 0;
    const resetTime = ttl > 0 ? Date.now() + ttl * 1000 : Date.now();
    const isJailed = jailVal !== null;

    return {
      count,
      resetTime,
      isJailed,
      jailUntil: isJailed ? resetTime : 0,
    };
  }

  public async jail(key: string, durationMs: number): Promise<void> {
    const jailKey = this.getJailKey(key);
    const ttlSec = Math.ceil(durationMs / 1000);
    await this.client.set(jailKey, '1', 'EX', ttlSec);
  }

  public async isJailed(key: string): Promise<boolean> {
    const jailKey = this.getJailKey(key);
    const val = await this.client.get(jailKey);
    return val !== null;
  }

  public async reset(key: string): Promise<void> {
    await Promise.all([
      this.client.del(this.getKey(key)),
      this.client.del(this.getJailKey(key)),
    ]);
  }
}
