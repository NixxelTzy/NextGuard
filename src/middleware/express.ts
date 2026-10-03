/**
 * NextGuard - Node.js Express / Connect / Fastify Middleware Adapter
 */

import { NextGuardConfig, RequestContext } from '../types.js';
import { NextGuardEngine } from '../core/engine.js';
import { getSecurityHeaders } from '../security/headers.js';
import { renderBlockedHtml, renderBlockedJson } from '../templates/blocked-page.js';

export interface ExpressRequest {
  url: string;
  originalUrl?: string;
  method: string;
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  query?: Record<string, unknown>;
  body?: unknown;
  socket?: { remoteAddress?: string };
}

export interface ExpressResponse {
  status: (code: number) => ExpressResponse;
  setHeader: (name: string, value: string) => ExpressResponse;
  json: (body: unknown) => void;
  send: (body: string) => void;
  headersSent?: boolean;
}

export type ExpressNextFunction = (err?: any) => void;

export function nextGuardExpress(config: NextGuardConfig = {}) {
  const engine = new NextGuardEngine(config);
  const secHeaders = getSecurityHeaders(config.securityHeaders);

  return async function nextGuardMiddleware(
    req: ExpressRequest,
    res: ExpressResponse,
    next: ExpressNextFunction
  ): Promise<void> {
    try {
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers || {})) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value[0] : (value as string);
      }

      const ip =
        headers['cf-connecting-ip'] ||
        headers['x-real-ip'] ||
        (headers['x-forwarded-for'] ? headers['x-forwarded-for'].split(',')[0].trim() : req.ip || req.socket?.remoteAddress || '127.0.0.1');

      const ctx: RequestContext = {
        url: req.originalUrl || req.url || '/',
        method: req.method || 'GET',
        ip,
        headers,
        query: req.query,
        body: req.body,
      };

      const verdict = await engine.inspect(ctx);

      // Set security headers on all responses
      for (const [headerName, headerValue] of Object.entries(secHeaders)) {
        res.setHeader(headerName, headerValue);
      }

      if (!verdict.allowed) {
        // Layer 7: Active Exploit Neutralizer & Crash Terminator
        if (config.sevenLayerShield) {
          const neutralized = engine.getShield().neutralizeExploit(verdict);
          for (const [hName, hVal] of Object.entries(neutralized.headers)) {
            res.setHeader(hName, hVal);
          }
          if (neutralized.shouldDestroySocket && (req as any).socket?.destroy) {
            (req as any).socket.destroy();
            return;
          }
          res.status(neutralized.statusCode).json(neutralized.body);
          return;
        }

        const accept = headers['accept'] || '';
        const isHtml = config.htmlResponse && accept.includes('text/html');

        if (isHtml) {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.status(verdict.statusCode).send(renderBlockedHtml(verdict));
          return;
        }

        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.status(verdict.statusCode).json(renderBlockedJson(verdict));
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}
