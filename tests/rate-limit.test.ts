import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter } from '../src/core/rate-limiter.js';
import { MemoryStore } from '../src/core/stores/memory-store.js';
import { RequestContext } from '../src/types.js';

describe('RateLimiter & DoS Protection', () => {
  let rateLimiter: RateLimiter;
  let store: MemoryStore;

  const mockReq: RequestContext = {
    url: '/api/login',
    method: 'POST',
    ip: '192.168.1.100',
    headers: {},
  };

  beforeEach(() => {
    store = new MemoryStore();
    rateLimiter = new RateLimiter({
      enabled: true,
      windowMs: 1000, // 1 second window
      max: 5, // max 5 requests
      jailThreshold: 10, // jail at 10 requests
      jailDurationMs: 2000,
      store,
    });
  });

  it('should allow requests under the limit', async () => {
    for (let i = 1; i <= 5; i++) {
      const res = await rateLimiter.check(mockReq);
      expect(res.allowed).toBe(true);
      expect(res.remaining).toBe(5 - i);
    }
  });

  it('should block requests exceeding the max limit', async () => {
    // Fire 5 allowed requests
    for (let i = 0; i < 5; i++) {
      await rateLimiter.check(mockReq);
    }

    // 6th request should be blocked
    const blockedRes = await rateLimiter.check(mockReq);
    expect(blockedRes.allowed).toBe(false);
    expect(blockedRes.remaining).toBe(0);
    expect(blockedRes.isJailed).toBe(false);
    expect(blockedRes.retryAfterSec).toBeGreaterThan(0);
  });

  it('should automatically jail DoS / flood attacks exceeding jailThreshold', async () => {
    // Send 10 rapid requests (jail threshold)
    for (let i = 0; i < 9; i++) {
      await rateLimiter.check(mockReq);
    }

    // 10th request triggers jail
    const jailRes = await rateLimiter.check(mockReq);
    expect(jailRes.allowed).toBe(false);
    expect(jailRes.isJailed).toBe(true);

    // Subsequent requests remain jailed
    const subsequentRes = await rateLimiter.check(mockReq);
    expect(subsequentRes.allowed).toBe(false);
    expect(subsequentRes.isJailed).toBe(true);
  });

  it('should isolate rate limits per IP', async () => {
    const reqA: RequestContext = { ...mockReq, ip: '1.1.1.1' };
    const reqB: RequestContext = { ...mockReq, ip: '2.2.2.2' };

    // Max out reqA
    for (let i = 0; i < 5; i++) {
      await rateLimiter.check(reqA);
    }
    const reqABlocked = await rateLimiter.check(reqA);
    expect(reqABlocked.allowed).toBe(false);

    // reqB should still be allowed
    const reqBResult = await rateLimiter.check(reqB);
    expect(reqBResult.allowed).toBe(true);
    expect(reqBResult.remaining).toBe(4);
  });
});
