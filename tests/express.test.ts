import { describe, it, expect, vi } from 'vitest';
import { nextGuardExpress } from '../src/middleware/express.js';

describe('Express Middleware Adapter', () => {
  const middleware = nextGuardExpress({
    rateLimit: { max: 5 },
  });

  function createMockResponse() {
    const res: any = {
      statusCode: 200,
      headers: {} as Record<string, string>,
      body: null,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      setHeader(k: string, v: string) {
        this.headers[k.toLowerCase()] = v;
        return this;
      },
      json(data: any) {
        this.body = data;
        return this;
      },
      send(data: string) {
        this.body = data;
        return this;
      },
    };
    return res;
  }

  it('should block SQL injection in query params and stop pipeline', async () => {
    const req: any = {
      url: '/search',
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0',
      },
      query: {
        q: "1' UNION SELECT username, password FROM users --",
      },
      ip: '10.0.0.1',
    };

    const res = createMockResponse();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.body.threat).toBe('sql_injection');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('should allow legitimate requests and call next()', async () => {
    const req: any = {
      url: '/search',
      method: 'GET',
      headers: {
        'user-agent': 'Mozilla/5.0',
      },
      query: {
        q: 'macbook pro 16',
      },
      ip: '10.0.0.2',
    };

    const res = createMockResponse();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-frame-options']).toBe('DENY');
  });
});
