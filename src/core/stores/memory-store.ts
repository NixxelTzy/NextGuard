/**
 * NextGuard - In-Memory Sliding Window Store
 * High-performance, zero-dependency store with automated garbage collection.
 */

import { RateLimitStore, RateLimitEntry } from '../../types.js';

interface InternalEntry {
  count: number;
  resetTime: number;
  isJailed: boolean;
  jailUntil: number;
}

export class MemoryStore implements RateLimitStore {
  private map: Map<string, InternalEntry> = new Map();
  private gcInterval: ReturnType<typeof setInterval> | null = null;

  constructor(gcIntervalMs = 30000) {
    // Only setup interval if in an environment with timers (Node.js/Edge supports setInterval)
    if (typeof setInterval !== 'undefined') {
      this.gcInterval = setInterval(() => this.cleanup(), gcIntervalMs);
      if (this.gcInterval && typeof this.gcInterval.unref === 'function') {
        this.gcInterval.unref(); // Prevent blocking Node.js event loop shutdown
      }
    }
  }

  public async increment(key: string, windowMs: number): Promise<{ count: number; resetTime: number }> {
    const now = Date.now();
    let entry = this.map.get(key);

    if (!entry || now > entry.resetTime) {
      entry = {
        count: 1,
        resetTime: now + windowMs,
        isJailed: false,
        jailUntil: 0,
      };
      this.map.set(key, entry);
      return { count: 1, resetTime: entry.resetTime };
    }

    entry.count += 1;
    return { count: entry.count, resetTime: entry.resetTime };
  }

  public async get(key: string): Promise<RateLimitEntry | null> {
    const entry = this.map.get(key);
    if (!entry) return null;

    const now = Date.now();
    if (now > entry.resetTime && (!entry.isJailed || now > entry.jailUntil)) {
      this.map.delete(key);
      return null;
    }

    return {
      count: entry.count,
      resetTime: entry.resetTime,
      isJailed: entry.isJailed && now < entry.jailUntil,
      jailUntil: entry.jailUntil,
    };
  }

  public async jail(key: string, durationMs: number): Promise<void> {
    const now = Date.now();
    const entry = this.map.get(key);
    const jailUntil = now + durationMs;

    if (entry) {
      entry.isJailed = true;
      entry.jailUntil = jailUntil;
    } else {
      this.map.set(key, {
        count: 1,
        resetTime: jailUntil,
        isJailed: true,
        jailUntil,
      });
    }
  }

  public async isJailed(key: string): Promise<boolean> {
    const entry = this.map.get(key);
    if (!entry || !entry.isJailed) return false;

    if (Date.now() > entry.jailUntil) {
      entry.isJailed = false;
      return false;
    }

    return true;
  }

  public async reset(key: string): Promise<void> {
    this.map.delete(key);
  }

  public cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.map.entries()) {
      if (now > entry.resetTime && (!entry.isJailed || now > entry.jailUntil)) {
        this.map.delete(key);
      }
    }
  }

  public destroy(): void {
    if (this.gcInterval) {
      clearInterval(this.gcInterval);
      this.gcInterval = null;
    }
    this.map.clear();
  }
}
