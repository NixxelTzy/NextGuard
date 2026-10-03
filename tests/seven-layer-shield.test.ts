import { describe, it, expect } from 'vitest';
import { SevenLayerShield } from '../src/core/seven-layer-shield.js';
import { NextGuardEngine } from '../src/core/engine.js';
import { NextGuard as NextGuardNode } from '../packages/node/src/index.js';
import { NextGuard as NextGuardNext } from '../packages/next/src/index.js';
import { RequestContext, InspectionVerdict } from '../src/types.js';

describe('SevenLayerShield (7-Layer Defense-in-Depth)', () => {
  const shield = new SevenLayerShield();

  describe('Layer 2: Protocol & Method Sanitization', () => {
    it('blocks dangerous HTTP verbs (TRACE, TRACK, CONNECT, DEBUG)', () => {
      const dangerousVerbs = ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'];

      for (const method of dangerousVerbs) {
        const req: RequestContext = {
          url: '/api/users',
          method,
          ip: '127.0.0.1',
          headers: {},
        };

        const res = shield.inspectProtocol(req);
        expect(res.passed).toBe(false);
        expect(res.layer).toBe('L2_PROTOCOL_SANITIZER');
        expect(res.statusCode).toBe(405);
      }
    });

    it('blocks arbitrary non-whitelisted HTTP methods', () => {
      const req: RequestContext = {
        url: '/api/users',
        method: 'PROPFIND_ARBITRARY',
        ip: '127.0.0.1',
        headers: {},
      };

      const res = shield.inspectProtocol(req);
      expect(res.passed).toBe(false);
      expect(res.statusCode).toBe(405);
    });

    it('detects HTTP Request Smuggling (Conflicting Content-Length and Transfer-Encoding)', () => {
      const req: RequestContext = {
        url: '/api/payment',
        method: 'POST',
        ip: '127.0.0.1',
        headers: {
          'content-length': '42',
          'transfer-encoding': 'chunked',
        },
      };

      const res = shield.inspectProtocol(req);
      expect(res.passed).toBe(false);
      expect(res.reason).toContain('HTTP Request Smuggling');
      expect(res.statusCode).toBe(400);
    });

    it('detects CRLF header splitting injection', () => {
      const req: RequestContext = {
        url: '/api/login',
        method: 'POST',
        ip: '127.0.0.1',
        headers: {
          'x-forwarded-host': 'legit.com\r\nInjected-Header: evil',
        },
      };

      const res = shield.inspectProtocol(req);
      expect(res.passed).toBe(false);
      expect(res.reason).toContain('CRLF injection');
      expect(res.statusCode).toBe(400);
    });

    it('detects null-byte injection in headers', () => {
      const req: RequestContext = {
        url: '/api/login',
        method: 'GET',
        ip: '127.0.0.1',
        headers: {
          'x-custom': 'payload\0malicious',
        },
      };

      const res = shield.inspectProtocol(req);
      expect(res.passed).toBe(false);
      expect(res.reason).toContain('Null byte injection');
    });

    it('passes standard, legitimate HTTP requests', () => {
      const legitVerbs = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

      for (const method of legitVerbs) {
        const req: RequestContext = {
          url: '/api/items',
          method,
          ip: '127.0.0.1',
          headers: {
            'user-agent': 'Mozilla/5.0 Chrome/120',
            'content-type': 'application/json',
          },
        };

        const res = shield.inspectProtocol(req);
        expect(res.passed).toBe(true);
      }
    });
  });

  describe('Layer 7: Active Exploit Neutralizer & Crash Terminator', () => {
    const sampleVerdict: InspectionVerdict = {
      allowed: false,
      threatType: 'command_injection',
      reason: 'Remote OS Command Injection detected',
      statusCode: 403,
      clientIp: '198.51.100.99',
      requestId: 'test_req_123',
      timestamp: Date.now(),
      mode: 'enforce',
    };

    it('synthesizes hard error response to crash exploit scripts (synthetic_error mode)', () => {
      const s = new SevenLayerShield({ neutralizeMode: 'synthetic_error' });
      const resp = s.neutralizeExploit(sampleVerdict);

      expect(resp.statusCode).toBe(400);
      expect(resp.headers['Connection']).toBe('close');
      expect(resp.headers['X-NextGuard-Shield']).toBe('L7-Neutralized');

      const body = resp.body as Record<string, unknown>;
      expect(body.error).toBe('ERR_EXPLOIT_PAYLOAD_NEUTRALIZED');
      expect(body.code).toBe('E_EXPLOIT_ABORTED');
      expect(body.threat).toBe('command_injection');
      expect(body.status).toBe('attack_intercepted');
    });

    it('marks socket for immediate destruction in abort_stream mode (ECONNRESET)', () => {
      const s = new SevenLayerShield({ neutralizeMode: 'abort_stream' });
      const resp = s.neutralizeExploit(sampleVerdict);

      expect(resp.shouldDestroySocket).toBe(true);
      expect(resp.headers['Connection']).toBe('close');
    });

    it('de-weaponizes hazardous tokens in strings', () => {
      const dangerous = 'SELECT * FROM users WHERE id = 1 OR 1=1; exec("cat /etc/passwd")';
      const clean = shield.deweaponizeString(dangerous);

      expect(clean).toContain('[BLOCKED_SELECT]');
      expect(clean).toContain('[BLOCKED_OR]');
      expect(clean).toContain('[NEUTRALIZED_exec]');
      expect(clean).not.toContain('exec(');
    });
  });

  describe('Engine & Package Integration', () => {
    it('engine blocks TRACE request via Layer 2 Protocol Sanitization', async () => {
      const engine = new NextGuardEngine({
        sevenLayerShield: { enabled: true },
      });

      const req: RequestContext = {
        url: '/api/users',
        method: 'TRACE',
        ip: '127.0.0.1',
        headers: {},
      };

      const verdict = await engine.inspect(req);
      expect(verdict.allowed).toBe(false);
      expect(verdict.statusCode).toBe(405);
      expect(verdict.reason).toContain('Protocol Sanitizer');
    });

    it('@nextguard/node returns neutralized exploit error when sevenLayerShield is enabled', async () => {
      const guard = NextGuardNode({
        logging: false,
        sqlInjection: { enabled: true },
        sevenLayerShield: { enabled: true, neutralizeMode: 'synthetic_error' },
      });

      const mw = guard.middleware();
      let sentStatus = 0;
      let sentJson: any = null;
      let headersSet: Record<string, string> = {};

      const mockReq: any = {
        method: 'POST',
        url: '/api/login',
        headers: { 'user-agent': 'Mozilla/5.0' },
        body: { username: "' OR 1=1 --" },
        socket: { remoteAddress: '192.0.2.77' },
      };

      const mockRes: any = {
        status(code: number) {
          sentStatus = code;
          return this;
        },
        setHeader(k: string, v: string) {
          headersSet[k] = v;
          return this;
        },
        json(data: any) {
          sentJson = data;
        },
      };

      await mw(mockReq, mockRes, () => {});

      expect(sentStatus).toBe(400);
      expect(sentJson.error).toBe('ERR_EXPLOIT_PAYLOAD_NEUTRALIZED');
      expect(sentJson.code).toBe('E_EXPLOIT_ABORTED');
      expect(headersSet['Connection']).toBe('close');
      expect(headersSet['X-NextGuard-Shield']).toBe('L7-Neutralized');
    });

    it('@nextguard/next returns neutralized exploit error in Next.js middleware', async () => {
      const guard = NextGuardNext({
        logging: false,
        sqlInjection: { enabled: true },
        sevenLayerShield: { enabled: true, neutralizeMode: 'synthetic_error' },
      });

      const handler = guard.middleware();
      const req = new Request('https://example.com/api/test?q=1%27%20OR%201=1--', {
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0' },
      });

      const res = await handler(req);
      expect(res).toBeInstanceOf(Response);
      expect(res!.status).toBe(400);
      expect(res!.headers.get('Connection')).toBe('close');
      expect(res!.headers.get('X-NextGuard-Shield')).toBe('L7-Neutralized');

      const body = await res!.json();
      expect(body.error).toBe('ERR_EXPLOIT_PAYLOAD_NEUTRALIZED');
      expect(body.code).toBe('E_EXPLOIT_ABORTED');
    });
  });
});
