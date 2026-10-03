/**
 * NextGuard - Node.js Express / Connect / Fastify Middleware Adapter
 */
import { NextGuardConfig } from '../types.js';
export interface ExpressRequest {
    url: string;
    originalUrl?: string;
    method: string;
    headers: Record<string, string | string[] | undefined>;
    ip?: string;
    query?: Record<string, unknown>;
    body?: unknown;
    socket?: {
        remoteAddress?: string;
    };
}
export interface ExpressResponse {
    status: (code: number) => ExpressResponse;
    setHeader: (name: string, value: string) => ExpressResponse;
    json: (body: unknown) => void;
    send: (body: string) => void;
    headersSent?: boolean;
}
export type ExpressNextFunction = (err?: any) => void;
export declare function nextGuardExpress(config?: NextGuardConfig): (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => Promise<void>;
//# sourceMappingURL=express.d.ts.map