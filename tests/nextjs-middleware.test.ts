import { describe, it, expect } from 'vitest';
import { createNextGuardMiddleware, withNextGuard } from '../src/middleware/nextjs.js';

describe('Next.js Middleware & Route Protection', () => {
  describe('createNextGuardMiddleware', () => {
    const middleware = createNextGuardMiddleware({
      rateLimit: { max: 10 },
    });

    it('should block SQL injection in query params with 403', async () => {
      const req = new Request('https://example.com/api/users?search=1%27%20OR%201%3D1%20--', {
        method: 'GET',
        headers: {
          'user-agent': 'Mozilla/5.0 Chrome/120.0.0.0',
        },
      });

      const res = await middleware(req);
      expect(res).toBeDefined();
      expect(res?.status).toBe(403);

      const json = await res?.json();
      expect(json.code).toBe('FIREWALL_BLOCKED');
      expect(json.threat).toBe('sql_injection');
    });

    it('should block bad scanner user agent with 403', async () => {
      const req = new Request('https://example.com/api/users', {
        method: 'GET',
        headers: {
          'user-agent': 'sqlmap/1.4.7',
        },
      });

      const res = await middleware(req);
      expect(res).toBeDefined();
      expect(res?.status).toBe(403);

      const json = await res?.json();
      expect(json.threat).toBe('bad_bot');
    });

    it('should allow legitimate requests and return undefined (proceeding to route)', async () => {
      const req = new Request('https://example.com/api/users?search=laptop', {
        method: 'GET',
        headers: {
          'user-agent': 'Mozilla/5.0 Chrome/120.0.0.0',
        },
      });

      const res = await middleware(req);
      expect(res).toBeUndefined();
    });
  });

  describe('withNextGuard (App Router Route Handler)', () => {
    it('should inspect POST JSON body and block XSS attack', async () => {
      let handlerCalled = false;
      const handler = withNextGuard(async () => {
        handlerCalled = true;
        return Response.json({ success: true });
      });

      const maliciousReq = new Request('https://example.com/api/comments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
        },
        body: JSON.stringify({
          comment: '<script>alert(document.cookie)</script>',
        }),
      });

      const res = await handler(maliciousReq);
      expect(handlerCalled).toBe(false);
      expect(res.status).toBe(403);

      const json = await res.json();
      expect(json.threat).toBe('xss');
    });

    it('should pass clean requests through to handler and append security headers', async () => {
      let handlerCalled = false;
      const handler = withNextGuard(async () => {
        handlerCalled = true;
        return Response.json({ status: 'created' }, { status: 201 });
      });

      const cleanReq = new Request('https://example.com/api/comments', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
        },
        body: JSON.stringify({
          comment: 'This is a genuine comment about NextGuard!',
        }),
      });

      const res = await handler(cleanReq);
      expect(handlerCalled).toBe(true);
      expect(res.status).toBe(201);
      expect(res.headers.get('x-content-type-options')).toBe('nosniff');
      expect(res.headers.get('x-frame-options')).toBe('DENY');
    });
  });
});
