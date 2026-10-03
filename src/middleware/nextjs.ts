/**
 * NextGuard - Next.js Adapter
 * Supports Next.js Edge Middleware (`middleware.ts`), App Router Route Handlers, and Pages Router API Handlers.
 */

import { NextGuardConfig, RequestContext, InspectionVerdict } from '../types.js';
import { NextGuardEngine } from '../core/engine.js';
import { getSecurityHeaders } from '../security/headers.js';
import { renderBlockedHtml, renderBlockedJson } from '../templates/blocked-page.js';

// Minimal interface definitions compatible with NextRequest / Standard Web Request
export interface GenericNextRequest {
  url: string;
  method: string;
  headers: Headers;
  ip?: string;
  nextUrl?: {
    pathname: string;
    searchParams: URLSearchParams;
  };
  json?: () => Promise<unknown>;
  text?: () => Promise<string>;
  clone?: () => GenericNextRequest;
}

/**
 * Extracts RequestContext from standard Request or NextRequest
 */
export async function extractRequestContext(
  req: GenericNextRequest | Request,
  inspectBody = false
): Promise<RequestContext> {
  const url = req.url;
  const method = req.method;

  // Headers
  const headers: Record<string, string> = {};
  req.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  // Query Params
  const query: Record<string, string> = {};
  try {
    const urlObj = new URL(url);
    urlObj.searchParams.forEach((val, k) => {
      query[k] = val;
    });
  } catch {
    // Ignore parse error
  }

  // IP extraction
  const ip =
    ('ip' in req && typeof req.ip === 'string' ? req.ip : undefined) ||
    headers['cf-connecting-ip'] ||
    headers['x-real-ip'] ||
    (headers['x-forwarded-for'] ? headers['x-forwarded-for'].split(',')[0].trim() : '127.0.0.1');

  // Body extraction (for POST/PUT/PATCH/DELETE)
  let body: unknown = undefined;
  let rawBody: string | undefined = undefined;

  if (inspectBody && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
    try {
      const clonedReq = typeof req.clone === 'function' ? req.clone() : req;
      const contentType = headers['content-type'] || '';

      if (contentType.includes('application/json') && typeof clonedReq.json === 'function') {
        body = await clonedReq.json();
      } else if (typeof clonedReq.text === 'function') {
        rawBody = await clonedReq.text();
        try {
          body = JSON.parse(rawBody);
        } catch {
          // Keep rawBody
        }
      }
    } catch {
      // Body may already be consumed or unparseable
    }
  }

  return {
    url,
    method,
    ip,
    headers,
    query,
    body,
    rawBody,
  };
}

/**
 * Build standard Response for blocked verdict
 */
export function createBlockedResponse(
  verdict: InspectionVerdict,
  headers: Record<string, string> = {},
  preferHtml = false
): Response {
  const securityHeaders = getSecurityHeaders();
  const mergedHeaders = new Headers({
    ...securityHeaders,
    ...headers,
  });

  if (preferHtml) {
    mergedHeaders.set('Content-Type', 'text/html; charset=utf-8');
    return new Response(renderBlockedHtml(verdict), {
      status: verdict.statusCode,
      headers: mergedHeaders,
    });
  }

  mergedHeaders.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(renderBlockedJson(verdict)), {
    status: verdict.statusCode,
    headers: mergedHeaders,
  });
}

/**
 * 1. Global Middleware for Next.js (`middleware.ts`)
 * Usage:
 * ```ts
 * import { createNextGuardMiddleware } from 'nextguard';
 * export const middleware = createNextGuardMiddleware({ ... });
 * export const config = { matcher: ['/api/:path*', '/((?!_next/static|_next/image|favicon.ico).*)'] };
 * ```
 */
export function createNextGuardMiddleware(config: NextGuardConfig = {}) {
  const engine = new NextGuardEngine(config);
  const secHeaders = getSecurityHeaders(config.securityHeaders);

  return async function nextGuardMiddleware(req: GenericNextRequest | Request) {
    const ctx = await extractRequestContext(req, false);
    const verdict = await engine.inspect(ctx);

    if (!verdict.allowed) {
      const acceptHeader = req.headers.get('accept') || '';
      const isHtml = config.htmlResponse !== false && acceptHeader.includes('text/html');
      return createBlockedResponse(verdict, {}, isHtml);
    }

    // For allowed requests, we return undefined or allow next() with security headers
    // If running in Next.js, NextResponse can be imported or headers returned
    return undefined;
  };
}

/**
 * 2. Next.js App Router Route Handler Wrapper (`app/api/.../route.ts`)
 * Usage:
 * ```ts
 * import { withNextGuard } from 'nextguard';
 *
 * export const POST = withNextGuard(async (req) => {
 *   return Response.json({ status: 'ok' });
 * }, { rateLimit: { max: 10 } });
 * ```
 */
export type AppRouteHandler = (req: Request, context?: any) => Promise<Response> | Response;

export function withNextGuard(
  handler: AppRouteHandler,
  endpointConfig: NextGuardConfig = {}
): AppRouteHandler {
  const engine = new NextGuardEngine(endpointConfig);
  const secHeaders = getSecurityHeaders(endpointConfig.securityHeaders);

  return async function wrappedRouteHandler(req: Request, context?: any): Promise<Response> {
    const ctx = await extractRequestContext(req as GenericNextRequest, true);
    const verdict = await engine.inspect(ctx);

    if (!verdict.allowed) {
      const accept = req.headers.get('accept') || '';
      const isHtml = endpointConfig.htmlResponse && accept.includes('text/html');
      return createBlockedResponse(verdict, {}, isHtml);
    }

    const response = await handler(req, context);

    // Apply security headers
    for (const [key, value] of Object.entries(secHeaders)) {
      if (!response.headers.has(key)) {
        response.headers.set(key, value);
      }
    }

    return response;
  };
}

/**
 * 3. Next.js Pages Router API Handler Wrapper (`pages/api/...ts`)
 * Usage:
 * ```ts
 * import { withNextGuardPages } from 'nextguard';
 *
 * async function handler(req, res) {
 *   res.status(200).json({ status: 'ok' });
 * }
 * export default withNextGuardPages(handler);
 * ```
 */
export function withNextGuardPages(
  handler: (req: any, res: any) => Promise<void> | void,
  endpointConfig: NextGuardConfig = {}
) {
  const engine = new NextGuardEngine(endpointConfig);
  const secHeaders = getSecurityHeaders(endpointConfig.securityHeaders);

  return async function wrappedPagesHandler(req: any, res: any): Promise<void> {
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers || {})) {
      headers[key.toLowerCase()] = Array.isArray(value) ? value[0] : (value as string);
    }

    const ip =
      req.headers['cf-connecting-ip'] ||
      req.headers['x-real-ip'] ||
      (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.socket?.remoteAddress || '127.0.0.1');

    const ctx: RequestContext = {
      url: req.url || '/',
      method: req.method || 'GET',
      ip,
      headers,
      query: req.query,
      body: req.body,
    };

    const verdict = await engine.inspect(ctx);

    if (!verdict.allowed) {
      const accept = headers['accept'] || '';
      const isHtml = endpointConfig.htmlResponse && accept.includes('text/html');

      // Set security headers
      for (const [k, v] of Object.entries(secHeaders)) {
        res.setHeader(k, v);
      }

      if (isHtml) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.status(verdict.statusCode).send(renderBlockedHtml(verdict));
        return;
      }

      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.status(verdict.statusCode).json(renderBlockedJson(verdict));
      return;
    }

    // Apply security headers
    for (const [k, v] of Object.entries(secHeaders)) {
      res.setHeader(k, v);
    }

    return handler(req, res);
  };
}
