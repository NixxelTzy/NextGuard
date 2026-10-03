/**
 * NextGuard - Next.js Adapter
 * Supports Next.js Edge Middleware (`middleware.ts`), App Router Route Handlers, and Pages Router API Handlers.
 */
import { NextGuardConfig, RequestContext, InspectionVerdict } from '../types.js';
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
export declare function extractRequestContext(req: GenericNextRequest | Request, inspectBody?: boolean): Promise<RequestContext>;
/**
 * Build standard Response for blocked verdict
 */
export declare function createBlockedResponse(verdict: InspectionVerdict, headers?: Record<string, string>, preferHtml?: boolean): Response;
/**
 * 1. Global Middleware for Next.js (`middleware.ts`)
 * Usage:
 * ```ts
 * import { createNextGuardMiddleware } from 'nextguard';
 * export const middleware = createNextGuardMiddleware({ ... });
 * export const config = { matcher: ['/api/:path*', '/((?!_next/static|_next/image|favicon.ico).*)'] };
 * ```
 */
export declare function createNextGuardMiddleware(config?: NextGuardConfig): (req: GenericNextRequest | Request) => Promise<Response | undefined>;
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
export declare function withNextGuard(handler: AppRouteHandler, endpointConfig?: NextGuardConfig): AppRouteHandler;
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
export declare function withNextGuardPages(handler: (req: any, res: any) => Promise<void> | void, endpointConfig?: NextGuardConfig): (req: any, res: any) => Promise<void>;
//# sourceMappingURL=nextjs.d.ts.map