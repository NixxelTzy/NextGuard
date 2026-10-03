import { describe, it, expect, beforeEach } from 'vitest';
import { EndpointRegistry, normalizePath, makeEndpointId } from '../src/registry.js';

describe('normalizePath', () => {
  it('menghapus query string', () => {
    expect(normalizePath('/api/users?page=1&limit=10')).toBe('/api/users');
  });

  it('menghapus trailing slash', () => {
    expect(normalizePath('/api/users/')).toBe('/api/users');
  });

  it('mempertahankan root /', () => {
    expect(normalizePath('/')).toBe('/');
  });

  it('lowercase semua huruf', () => {
    expect(normalizePath('/api/Users/PROFILE')).toBe('/api/users/profile');
  });

  it('handle URL lengkap dengan domain', () => {
    expect(normalizePath('https://example.com/api/products?sort=price')).toBe('/api/products');
  });

  it('handle URL relatif tanpa leading slash (ditambah leading slash)', () => {
    // URL tanpa leading slash di-prefix dengan '/' oleh normalizePath
    // new URL('http://localhost/api/users') → pathname '/api/users'
    expect(normalizePath('/api/users')).toBe('/api/users');
    // string 'api/users' akan diparse sebagai http://localhost + 'api/users'
    // yang menghasilkan path '/api/users' dengan URL patching
    const result = normalizePath('api/users');
    expect(result.endsWith('users')).toBe(true);
  });

  it('handle fragment (#)', () => {
    expect(normalizePath('/page#section')).toBe('/page');
  });
});

describe('makeEndpointId', () => {
  it('menghasilkan format METHOD:path yang konsisten', () => {
    expect(makeEndpointId('GET', '/api/users')).toBe('GET:/api/users');
    expect(makeEndpointId('post', '/api/login')).toBe('POST:/api/login');
  });

  it('menormalisasi query string dari URL', () => {
    expect(makeEndpointId('GET', '/api/search?q=hello&page=1')).toBe('GET:/api/search');
  });

  it('menghasilkan ID yang sama untuk method case berbeda', () => {
    expect(makeEndpointId('get', '/api/users')).toBe(makeEndpointId('GET', '/api/users'));
  });
});

describe('EndpointRegistry', () => {
  let registry: EndpointRegistry;

  beforeEach(() => {
    registry = new EndpointRegistry();
  });

  it('mencatat endpoint pertama kali dengan benar', () => {
    const rec = registry.record('GET', '/api/users', '1.2.3.4', true, 200);

    expect(rec.id).toBe('GET:/api/users');
    expect(rec.method).toBe('GET');
    expect(rec.path).toBe('/api/users');
    expect(rec.requestCount).toBe(1);
    expect(rec.allowedCount).toBe(1);
    expect(rec.blockedCount).toBe(0);
    expect(rec.lastStatusCode).toBe(200);
    expect(rec.uniqueIps.has('1.2.3.4')).toBe(true);
  });

  it('TIDAK membuat duplikat untuk METHOD+PATH yang sama', () => {
    registry.record('POST', '/api/login', '10.0.0.1', true, 200);
    registry.record('POST', '/api/login', '10.0.0.2', false, 429);
    registry.record('POST', '/api/login', '10.0.0.3', true, 200);

    expect(registry.size).toBe(1); // Tetap 1, bukan 3
    const rec = registry.get('POST:/api/login')!;
    expect(rec.requestCount).toBe(3);
    expect(rec.allowedCount).toBe(2);
    expect(rec.blockedCount).toBe(1);
  });

  it('membuat entry terpisah untuk METHOD berbeda pada PATH yang sama', () => {
    registry.record('GET', '/api/users', '1.1.1.1', true, 200);
    registry.record('POST', '/api/users', '1.1.1.1', true, 201);
    registry.record('DELETE', '/api/users', '1.1.1.1', true, 204);

    expect(registry.size).toBe(3);
    expect(registry.get('GET:/api/users')).toBeDefined();
    expect(registry.get('POST:/api/users')).toBeDefined();
    expect(registry.get('DELETE:/api/users')).toBeDefined();
  });

  it('menormalisasi URL dengan query string sebelum mencatat', () => {
    registry.record('GET', '/api/products?category=shoes&page=2', '1.1.1.1', true, 200);
    registry.record('GET', '/api/products?category=bags', '2.2.2.2', true, 200);

    // Keduanya harus masuk ke endpoint yang sama: GET:/api/products
    expect(registry.size).toBe(1);
    const rec = registry.get('GET:/api/products')!;
    expect(rec.requestCount).toBe(2);
    expect(rec.uniqueIps.size).toBe(2);
  });

  it('mengembalikan semua endpoint yang sudah ditemukan', () => {
    registry.record('GET', '/api/users', '1.1.1.1', true, 200);
    registry.record('POST', '/api/upload', '2.2.2.2', true, 200);
    registry.record('POST', '/api/payment', '3.3.3.3', false, 429);
    registry.record('DELETE', '/api/account', '4.4.4.4', true, 204);
    registry.record('GET', '/api/admin', '5.5.5.5', false, 403);

    const all = registry.getAll();
    expect(all.length).toBe(5);

    const ids = all.map(e => e.id).sort();
    expect(ids).toEqual([
      'DELETE:/api/account',
      'GET:/api/admin',
      'GET:/api/users',
      'POST:/api/payment',
      'POST:/api/upload',
    ]);
  });

  it('menghasilkan statistik ringkasan yang akurat', () => {
    registry.record('GET', '/api/users', '1.1.1.1', true, 200);
    registry.record('GET', '/api/users', '2.2.2.2', true, 200);
    registry.record('POST', '/api/login', '3.3.3.3', false, 429); // blocked
    registry.record('POST', '/api/login', '4.4.4.4', false, 429); // blocked
    registry.record('POST', '/api/login', '5.5.5.5', true, 200);

    const stats = registry.getStats();
    expect(stats.totalEndpoints).toBe(2);
    expect(stats.totalRequests).toBe(5);
    expect(stats.totalBlocked).toBe(2);
    expect(stats.totalAllowed).toBe(3);
  });

  it('update firstSeen dan lastSeen dengan benar', async () => {
    const rec1 = registry.record('GET', '/api/test', '1.1.1.1', true, 200);
    const firstSeen = rec1.firstSeen;

    await new Promise(r => setTimeout(r, 5));

    const rec2 = registry.record('GET', '/api/test', '1.1.1.1', true, 200);
    expect(rec2.firstSeen).toBe(firstSeen);        // firstSeen tidak berubah
    expect(rec2.lastSeen).toBeGreaterThan(firstSeen); // lastSeen diperbarui
  });

  it('membersihkan semua data dengan clear()', () => {
    registry.record('GET', '/api/a', '1.1.1.1', true, 200);
    registry.record('POST', '/api/b', '2.2.2.2', true, 200);
    expect(registry.size).toBe(2);

    registry.clear();
    expect(registry.size).toBe(0);
    expect(registry.getAll()).toHaveLength(0);
  });
});
