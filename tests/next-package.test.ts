import { describe, it, expect, beforeEach } from 'vitest';
import { NextGuard } from '../packages/next/src/index.js';

function makeRequest(method: string, url: string, headers: Record<string, string> = {}): Request {
  return new Request(`https://example.com${url}`, {
    method,
    headers: {
      'user-agent': 'Mozilla/5.0 Chrome/120',
      ...headers,
    },
  });
}

describe('@nextguard/next — NextGuard()', () => {
  it('guard.middleware() mengembalikan fungsi async', () => {
    const guard = NextGuard({ logging: false });
    const fn = guard.middleware();
    expect(typeof fn).toBe('function');
  });

  it('request bersih mengembalikan undefined (Next.js meneruskan ke route)', async () => {
    const guard = NextGuard({ logging: false });
    const handler = guard.middleware();

    const result = await handler(makeRequest('GET', '/api/users'));
    expect(result).toBeUndefined();
  });

  it('request dengan SQL Injection mengembalikan Response 403', async () => {
    const guard = NextGuard({
      logging: false,
      sqlInjection: { enabled: true, sensitivity: 'medium' },
    });
    const handler = guard.middleware();

    const result = await handler(makeRequest('GET', "/api/search?q=1' OR 1=1 --"));
    expect(result).toBeInstanceOf(Response);
    expect(result!.status).toBe(403);

    const body = await result!.json();
    expect(body.code).toBe('FIREWALL_BLOCKED');
    expect(body.threat).toBe('sql_injection');
  });

  it('bad bot scanner diblokir 403', async () => {
    const guard = NextGuard({
      logging: false,
      badBots: { enabled: true, knownScanners: true },
    });
    const handler = guard.middleware();

    const result = await handler(makeRequest('GET', '/api/users', {
      'user-agent': 'sqlmap/1.4.7',
    }));
    expect(result).toBeInstanceOf(Response);
    expect(result!.status).toBe(403);
  });

  it('auto-discovery: endpoint dicatat dari request aktual yang masuk', async () => {
    const guard = NextGuard({ logging: false });
    const handler = guard.middleware();

    // Simulasikan traffic aktual ke berbagai endpoint
    await handler(makeRequest('GET',    '/api/users'));
    await handler(makeRequest('POST',   '/api/upload'));
    await handler(makeRequest('POST',   '/api/payment'));
    await handler(makeRequest('DELETE', '/api/account'));
    await handler(makeRequest('GET',    '/api/random-endpoint'));

    const discovered = guard.getDiscoveredEndpoints();
    expect(discovered.length).toBe(5);

    const ids = discovered.map(e => e.id);
    expect(ids).toContain('GET:/api/users');
    expect(ids).toContain('POST:/api/upload');
    expect(ids).toContain('POST:/api/payment');
    expect(ids).toContain('DELETE:/api/account');
    expect(ids).toContain('GET:/api/random-endpoint');
  });

  it('auto-discovery: path yang sama = satu endpoint (tidak duplikat)', async () => {
    const guard = NextGuard({ logging: false });
    const handler = guard.middleware();

    // 5 request ke endpoint yang sama
    for (let i = 0; i < 5; i++) {
      await handler(makeRequest('GET', '/api/products'));
    }

    const discovered = guard.getDiscoveredEndpoints();
    expect(discovered.length).toBe(1);
    expect(discovered[0].requestCount).toBe(5);
  });

  it('auto-discovery: query string dihapus saat normalisasi path', async () => {
    const guard = NextGuard({ logging: false });
    const handler = guard.middleware();

    await handler(makeRequest('GET', '/api/search?q=hello'));
    await handler(makeRequest('GET', '/api/search?q=world&page=2'));
    await handler(makeRequest('GET', '/api/search'));

    const discovered = guard.getDiscoveredEndpoints();
    expect(discovered.length).toBe(1);
    expect(discovered[0].id).toBe('GET:/api/search');
    expect(discovered[0].requestCount).toBe(3);
  });

  it('request diblokir → tercatat sebagai blocked di registry', async () => {
    const guard = NextGuard({
      logging: false,
      sqlInjection: { enabled: true, sensitivity: 'medium' },
    });
    const handler = guard.middleware();

    await handler(makeRequest('GET', '/api/users')); // allowed
    await handler(makeRequest('GET', "/api/users?id=1' OR 1=1--")); // blocked

    // Keduanya masuk ke endpoint yang sama (karena query strip)
    const rec = guard.registry.get('GET:/api/users');
    expect(rec).toBeDefined();
    expect(rec!.requestCount).toBe(2);
    expect(rec!.allowedCount).toBe(1);
    expect(rec!.blockedCount).toBe(1);
  });

  it('response blocked menyertakan security headers', async () => {
    const guard = NextGuard({
      logging: false,
      sqlInjection: { enabled: true },
      securityHeaders: { enabled: true, xFrameOptions: 'DENY' },
    });
    const handler = guard.middleware();

    const result = await handler(makeRequest('GET', "/api/test?x=1' OR 1=1--"));
    expect(result).toBeInstanceOf(Response);
    expect(result!.headers.get('x-frame-options')).toBe('DENY');
    expect(result!.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('asset statis Next.js dikecualikan secara default', async () => {
    const guard = NextGuard({ logging: false });
    const handler = guard.middleware();

    // Asset /_next/ seharusnya dilewati dan tidak dicatat ke registry
    const result = await handler(makeRequest('GET', '/_next/static/chunk/main.js'));
    expect(result).toBeUndefined(); // Dilewati

    // Tidak dicatat ke registry karena sudah excluded
    expect(guard.registry.size).toBe(0);
  });

  it('getStats() mengembalikan statistik yang akurat', async () => {
    const guard = NextGuard({
      logging: false,
      sqlInjection: { enabled: true, sensitivity: 'medium' },
    });
    const handler = guard.middleware();

    await handler(makeRequest('GET', '/api/a'));
    await handler(makeRequest('GET', '/api/b'));
    await handler(makeRequest('POST', '/api/c'));
    await handler(makeRequest('GET', "/api/d?q=1' OR 1=1--")); // blocked

    const stats = guard.getStats();
    expect(stats.totalEndpoints).toBe(4);
    expect(stats.totalRequests).toBe(4);
    expect(stats.totalBlocked).toBe(1);
    expect(stats.totalAllowed).toBe(3);
  });
});
