import { describe, it, expect } from 'vitest';
import { HoneypotTrap } from '../src/core/honeypot.js';
import { NextGuardEngine } from '../src/core/engine.js';
import { RequestContext } from '../src/types.js';

describe('HoneypotTrap (Active Deception)', () => {
  const trap = new HoneypotTrap(true);

  it('should identify scanner tripwire endpoints', () => {
    const maliciousPaths = [
      '/.env',
      '/.env.local',
      '/.git/config',
      '/.git/HEAD',
      '/wp-admin/index.php',
      '/wp-login.php',
      '/phpmyadmin/index.php',
      '/pma',
      '/.aws/credentials',
      '/actuator/health',
      '/solr/admin',
      '/autodiscover/autodiscover.xml',
      '/backup.sql',
      '/dump.sql',
    ];

    for (const p of maliciousPaths) {
      expect(trap.isTrap(p), `Honeypot failed to catch: ${p}`).toBe(true);
    }
  });

  it('should allow legitimate application paths', () => {
    const legitPaths = [
      '/',
      '/login',
      '/api/users',
      '/products',
      '/about',
      '/contact',
      '/api/payment/checkout',
    ];

    for (const p of legitPaths) {
      expect(trap.isTrap(p), `Legitimate path falsely triggered honeypot: ${p}`).toBe(false);
    }
  });

  it('engine should immediately block and jail IP when honeypot is touched', async () => {
    const engine = new NextGuardEngine({
      honeypot: { enabled: true, jailDurationMs: 60 * 60 * 1000 },
    });

    const maliciousReq: RequestContext = {
      url: '/.env',
      method: 'GET',
      ip: '203.0.113.99',
      headers: { 'user-agent': 'curl/7.68.0' },
    };

    const verdict = await engine.inspect(maliciousReq);
    expect(verdict.allowed).toBe(false);
    expect(verdict.threatType).toBe('honeypot_triggered');
    expect(verdict.statusCode).toBe(403);

    // Subsequent legitimate request from the same IP should now be jailed!
    const subsequentReq: RequestContext = {
      url: '/api/users',
      method: 'GET',
      ip: '203.0.113.99',
      headers: { 'user-agent': 'Mozilla/5.0' },
    };

    const subsequentVerdict = await engine.inspect(subsequentReq);
    expect(subsequentVerdict.allowed).toBe(false);
    expect(subsequentVerdict.threatType).toBe('rate_limit_exceeded');
  });
});
