import { describe, it, expect, beforeEach } from 'vitest';
import { NextGuard } from '../packages/node/src/index.js';

// Mock response sederhana agar tidak butuh express
function createMockRes() {
  const res: any = {
    _status: 200,
    _headers: {} as Record<string, string>,
    _body: null as unknown,
    status(code: number) { this._status = code; return this; },
    setHeader(k: string, v: string) { this._headers[k.toLowerCase()] = v; return this; },
    json(data: unknown) { this._body = data; return this; },
    send(data: string) { this._body = data; return this; },
  };
  return res;
}

function createMockReq(method: string, url: string, overrides: Record<string, unknown> = {}) {
  return {
    method,
    url,
    originalUrl: url,
    headers: { 'user-agent': 'Mozilla/5.0 Test', ...((overrides.headers as any) ?? {}) },
    query: {},
    body: {},
    socket: { remoteAddress: '10.0.0.1' },
    ...overrides,
  };
}

describe('@nextguard/node — NextGuard()', () => {
  it('guard.middleware() mengembalikan fungsi middleware', () => {
    const guard = NextGuard({ logging: false });
    const mw = guard.middleware();
    expect(typeof mw).toBe('function');
  });

  it('request bersih melewati middleware dan memanggil next()', async () => {
    const guard = NextGuard({ logging: false });
    const mw = guard.middleware();

    const req = createMockReq('GET', '/api/users');
    const res = createMockRes();
    let nextCalled = false;
    const next = () => { nextCalled = true; };

    await mw(req, res, next);
    expect(nextCalled).toBe(true);
  });

  it('request dengan SQL Injection diblokir (403)', async () => {
    const guard = NextGuard({ logging: false, sqlInjection: { enabled: true, sensitivity: 'medium' } });
    const mw = guard.middleware();

    const req = createMockReq('GET', "/api/search?q=1' OR 1=1 --");
    const res = createMockRes();
    let nextCalled = false;

    await mw(req, res, () => { nextCalled = true; });

    expect(nextCalled).toBe(false);
    expect(res._status).toBe(403);
  });

  it('auto-discovery: endpoint dicatat dari request aktual', async () => {
    const guard = NextGuard({ logging: false });
    const mw = guard.middleware();

    // Simulasikan berbagai request
    await mw(createMockReq('GET',    '/api/users'),   createMockRes(), () => {});
    await mw(createMockReq('POST',   '/api/upload'),  createMockRes(), () => {});
    await mw(createMockReq('POST',   '/api/payment'), createMockRes(), () => {});
    await mw(createMockReq('DELETE', '/api/account'), createMockRes(), () => {});
    await mw(createMockReq('GET',    '/api/admin'),   createMockRes(), () => {});

    const discovered = guard.getDiscoveredEndpoints();
    expect(discovered.length).toBe(5);

    const ids = discovered.map(e => e.id).sort();
    expect(ids).toContain('GET:/api/users');
    expect(ids).toContain('POST:/api/upload');
    expect(ids).toContain('POST:/api/payment');
    expect(ids).toContain('DELETE:/api/account');
    expect(ids).toContain('GET:/api/admin');
  });

  it('auto-discovery: query string dihapus dari path', async () => {
    const guard = NextGuard({ logging: false });
    const mw = guard.middleware();

    // Request ke path yang sama tapi beda query string
    await mw(createMockReq('GET', '/api/products?category=shoes&page=1'), createMockRes(), () => {});
    await mw(createMockReq('GET', '/api/products?category=bags'), createMockRes(), () => {});
    await mw(createMockReq('GET', '/api/products'), createMockRes(), () => {});

    // Harus jadi SATU endpoint, bukan 3
    const discovered = guard.getDiscoveredEndpoints();
    expect(discovered.length).toBe(1);
    expect(discovered[0].id).toBe('GET:/api/products');
    expect(discovered[0].requestCount).toBe(3);
  });

  it('auto-discovery: method berbeda = endpoint terpisah', async () => {
    const guard = NextGuard({ logging: false });
    const mw = guard.middleware();

    await mw(createMockReq('GET',    '/api/items'), createMockRes(), () => {});
    await mw(createMockReq('POST',   '/api/items'), createMockRes(), () => {});
    await mw(createMockReq('PUT',    '/api/items'), createMockRes(), () => {});
    await mw(createMockReq('DELETE', '/api/items'), createMockRes(), () => {});

    expect(guard.getDiscoveredEndpoints().length).toBe(4);
  });

  it('getStats() mengembalikan ringkasan yang akurat', async () => {
    const guard = NextGuard({
      logging: false,
      sqlInjection: { enabled: true, sensitivity: 'medium' },
    });
    const mw = guard.middleware();

    // 3 request normal → allowed
    await mw(createMockReq('GET', '/api/users'),   createMockRes(), () => {});
    await mw(createMockReq('GET', '/api/users'),   createMockRes(), () => {});
    await mw(createMockReq('GET', '/api/products'), createMockRes(), () => {});

    // 1 request SQLi → blocked
    await mw(createMockReq('GET', "/api/search?q=1' OR 1=1 --"), createMockRes(), () => {});

    const stats = guard.getStats();
    expect(stats.totalEndpoints).toBe(3); // users, products, search
    expect(stats.totalRequests).toBe(4);
    expect(stats.totalBlocked).toBe(1);
    expect(stats.totalAllowed).toBe(3);
  });

  it('guard.protect() menerapkan override hanya untuk path tertentu', async () => {
    const guard = NextGuard({ logging: false, rateLimit: { max: 100, windowMs: 60_000 } });

    // Override: login hanya boleh 0 request (untuk test blokir)
    guard.protect('/api/login', { rateLimit: { max: 0, windowMs: 60_000 } });

    const mw = guard.middleware();
    const res = createMockRes();
    let nextCalled = false;

    await mw(createMockReq('POST', '/api/login'), res, () => { nextCalled = true; });

    // /api/login seharusnya diblokir karena max:0
    expect(nextCalled).toBe(false);
    expect(res._status).toBe(429);
  });

  it('request ke path lain tidak terpengaruh oleh protect() path tertentu', async () => {
    const guard = NextGuard({ logging: false });
    guard.protect('/api/admin', { rateLimit: { max: 0, windowMs: 60_000 } });

    const mw = guard.middleware();
    const resUsers = createMockRes();
    let nextCalled = false;

    await mw(createMockReq('GET', '/api/users'), resUsers, () => { nextCalled = true; });
    expect(nextCalled).toBe(true); // /api/users tidak terpengaruh
  });

  it('security headers disertakan pada semua response', async () => {
    const guard = NextGuard({
      logging: false,
      securityHeaders: { enabled: true, xFrameOptions: 'DENY' },
    });
    const mw = guard.middleware();

    const res = createMockRes();
    await mw(createMockReq('GET', '/api/test'), res, () => {});

    expect(res._headers['x-frame-options']).toBe('DENY');
    expect(res._headers['x-content-type-options']).toBe('nosniff');
  });
});
