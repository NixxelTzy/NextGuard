import { describe, it, expect, beforeEach } from 'vitest';
import { DatabaseGuard, createDatabaseGuard } from '../src/core/database-guard.js';

describe('DatabaseGuard — Database Protection', () => {
  let guard: DatabaseGuard;

  beforeEach(() => {
    guard = new DatabaseGuard({
      maxWritesPerMinute: 3,
      maxReadsPerMinute: 5,
      maxPayloadSizeBytes: 200,
      maxFieldCount: 5,
      maxArrayLength: 3,
      maxNestingDepth: 3,
      preventDuplicateWrites: true,
      duplicateWindowMs: 2000,
      preventBulkExtraction: true,
    });
  });

  describe('Write Rate Limiting', () => {
    it('allows writes under the limit', async () => {
      for (let i = 0; i < 3; i++) {
        const result = await guard.inspect('1.2.3.4', 'POST', { name: `user${i}` }, `{"name":"user${i}"}`);
        expect(result.allowed).toBe(true);
      }
    });

    it('blocks writes that exceed the per-minute limit', async () => {
      // Exhaust the limit (3 writes)
      for (let i = 0; i < 3; i++) {
        await guard.inspect('1.2.3.5', 'POST', { n: i }, `{"n":${i}}`);
      }
      // 4th write should be blocked
      const result = await guard.inspect('1.2.3.5', 'POST', { n: 99 }, `{"n":99}`);
      expect(result.allowed).toBe(false);
      expect(result.statusCode).toBe(429);
      expect(result.reason).toContain('write rate limit exceeded');
    });

    it('blocks PUT and DELETE as write operations', async () => {
      for (let i = 0; i < 3; i++) await guard.inspect('5.5.5.5', 'PUT', { x: i }, `{"x":${i}}`);
      const result = await guard.inspect('5.5.5.5', 'DELETE', {}, '{}');
      expect(result.allowed).toBe(false);
      expect(result.statusCode).toBe(429);
    });
  });

  describe('Read Rate Limiting (Bulk Extraction Prevention)', () => {
    it('allows reads under the limit', async () => {
      for (let i = 0; i < 5; i++) {
        const result = await guard.inspect('2.2.2.2', 'GET');
        expect(result.allowed).toBe(true);
      }
    });

    it('blocks excessive GET requests (data scraping)', async () => {
      for (let i = 0; i < 5; i++) await guard.inspect('3.3.3.3', 'GET');
      const result = await guard.inspect('3.3.3.3', 'GET');
      expect(result.allowed).toBe(false);
      expect(result.statusCode).toBe(429);
      expect(result.reason).toContain('read rate limit exceeded');
    });
  });

  describe('Payload Size Protection', () => {
    it('blocks oversized payload', async () => {
      const largePayload = { data: 'x'.repeat(300) };
      const raw = JSON.stringify(largePayload);
      const result = await guard.inspect('4.4.4.4', 'POST', largePayload, raw);
      expect(result.allowed).toBe(false);
      expect(result.statusCode).toBe(413);
      expect(result.reason).toContain('Payload too large');
    });

    it('allows payload within size limit', async () => {
      const small = { name: 'ok' };
      const result = await guard.inspect('4.4.4.5', 'POST', small, JSON.stringify(small));
      expect(result.allowed).toBe(true);
    });
  });

  describe('Field Flooding Prevention', () => {
    it('blocks payload with too many fields', async () => {
      const body: Record<string, number> = {};
      for (let i = 0; i < 10; i++) body[`field${i}`] = i;
      const raw = JSON.stringify(body);
      const result = await guard.inspect('6.6.6.6', 'POST', body, raw);
      expect(result.allowed).toBe(false);
      expect(result.statusCode).toBe(400);
      expect(result.reason).toContain('Too many fields');
    });
  });

  describe('Array Flooding Prevention (Bulk Insert Detection)', () => {
    it('blocks payload with oversized array (bulk insert spam)', async () => {
      const body = { items: [1, 2, 3, 4, 5] }; // 5 items > maxArrayLength 3
      const raw = JSON.stringify(body);
      const result = await guard.inspect('7.7.7.7', 'POST', body, raw);
      expect(result.allowed).toBe(false);
      expect(result.statusCode).toBe(400);
      expect(result.reason).toContain('Bulk insert detected');
    });

    it('allows array within limit', async () => {
      const body = { items: [1, 2] };
      const result = await guard.inspect('7.7.7.8', 'POST', body, JSON.stringify(body));
      expect(result.allowed).toBe(true);
    });
  });

  describe('Nesting Depth Protection', () => {
    it('blocks deeply nested payloads', async () => {
      const deep = { a: { b: { c: { d: 'too deep' } } } }; // depth 4 > maxNestingDepth 3
      const raw = JSON.stringify(deep);
      const result = await guard.inspect('8.8.8.8', 'POST', deep, raw);
      expect(result.allowed).toBe(false);
      expect(result.statusCode).toBe(400);
      expect(result.reason).toContain('nesting depth');
    });
  });

  describe('Duplicate Write Prevention', () => {
    it('blocks identical payload from same IP within window', async () => {
      const body = { username: 'spammer', action: 'create' };
      const raw = JSON.stringify(body);

      const first = await guard.inspect('9.9.9.9', 'POST', body, raw);
      expect(first.allowed).toBe(true);

      // Second identical write immediately
      const second = await guard.inspect('9.9.9.9', 'POST', body, raw);
      expect(second.allowed).toBe(false);
      expect(second.statusCode).toBe(429);
      expect(second.reason).toContain('Duplicate write detected');
    });

    it('allows identical payload from DIFFERENT IPs', async () => {
      const body = { action: 'create' };
      const raw = JSON.stringify(body);

      await guard.inspect('10.0.0.1', 'POST', body, raw);
      const result = await guard.inspect('10.0.0.2', 'POST', body, raw);
      expect(result.allowed).toBe(true);
    });
  });

  describe('createDatabaseGuard factory', () => {
    it('creates a DatabaseGuard instance with custom config', () => {
      const dbGuard = createDatabaseGuard({
        maxWritesPerMinute: 50,
        maxPayloadSizeBytes: 1024 * 1024,
      });
      expect(dbGuard).toBeInstanceOf(DatabaseGuard);
    });

    it('creates a DatabaseGuard with default config when no args given', () => {
      const dbGuard = createDatabaseGuard();
      expect(dbGuard).toBeInstanceOf(DatabaseGuard);
    });
  });

  describe('protectNext() — Next.js integration', () => {
    it('returns undefined (allow) for safe GET requests', async () => {
      const dbGuard = createDatabaseGuard({ maxReadsPerMinute: 100 });
      const req = new Request('https://example.com/api/users', {
        method: 'GET',
        headers: { 'x-forwarded-for': '11.0.0.1' },
      });
      const result = await dbGuard.protectNext(req);
      expect(result).toBeUndefined();
    });

    it('returns 413 Response for oversized POST payload', async () => {
      const dbGuard = createDatabaseGuard({ maxPayloadSizeBytes: 50 });
      const body = JSON.stringify({ data: 'x'.repeat(100) });
      const req = new Request('https://example.com/api/users', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-for': '12.0.0.1',
        },
        body,
      });
      const result = await dbGuard.protectNext(req);
      expect(result).not.toBeUndefined();
      expect(result!.status).toBe(413);
      const json = await result!.json();
      expect(json.error).toBe('Database Protection');
    });

    it('returns 429 Response when write limit exceeded', async () => {
      const dbGuard = createDatabaseGuard({ maxWritesPerMinute: 2 });
      const makeReq = (ip: string) =>
        new Request('https://example.com/api/data', {
          method: 'POST',
          headers: { 'x-forwarded-for': ip, 'content-type': 'application/json' },
          body: JSON.stringify({ value: Math.random() }),
        });

      await dbGuard.protectNext(makeReq('13.0.0.1'));
      await dbGuard.protectNext(makeReq('13.0.0.1'));
      const result = await dbGuard.protectNext(makeReq('13.0.0.1'));
      expect(result).not.toBeUndefined();
      expect(result!.status).toBe(429);
      expect(result!.headers.get('Retry-After')).not.toBeNull();
    });
  });
});
