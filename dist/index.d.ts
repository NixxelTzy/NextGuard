/**
 * NextGuard - Web Application Firewall (WAF) & Endpoint Security for Next.js and Node.js
 *
 * @license MIT
 * @author NextGuard Team
 */
import { NextGuardConfig, RequestContext, InspectionVerdict } from './types.js';
import { NextGuardEngine } from './core/engine.js';
import { createNextGuardMiddleware, withNextGuard, withNextGuardPages } from './middleware/nextjs.js';
import { nextGuardExpress } from './middleware/express.js';
/**
 * Convenient NextGuard instance class
 */
export declare class NextGuard {
    private engine;
    private config;
    constructor(config?: NextGuardConfig);
    /**
     * Inspect a request context and return the firewall verdict
     */
    inspect(req: RequestContext): Promise<InspectionVerdict>;
    /**
     * Create Next.js global middleware (`middleware.ts`)
     */
    nextMiddleware(overrideConfig?: NextGuardConfig): (req: import("./middleware/nextjs.js").GenericNextRequest | Request) => Promise<Response | undefined>;
    /**
     * Protect Next.js App Router route handler (app/api/.../route.ts)
     */
    protectAppRoute(handler: Parameters<typeof withNextGuard>[0], overrideConfig?: NextGuardConfig): import("./middleware/nextjs.js").AppRouteHandler;
    /**
     * Protect Next.js Pages Router API handler (pages/api/...ts)
     */
    protectPagesRoute(handler: Parameters<typeof withNextGuardPages>[0], overrideConfig?: NextGuardConfig): (req: any, res: any) => Promise<void>;
    /**
     * Node.js Express / Connect middleware
     */
    express(overrideConfig?: NextGuardConfig): (req: import("./middleware/express.js").ExpressRequest, res: import("./middleware/express.js").ExpressResponse, next: import("./middleware/express.js").ExpressNextFunction) => Promise<void>;
    /**
     * Get underlying engine
     */
    getEngine(): NextGuardEngine;
}
export default NextGuard;
export { NextGuardEngine, createNextGuardMiddleware, withNextGuard, withNextGuardPages, nextGuardExpress, };
export { SQLInjectionDetector } from './core/detectors/sqli.js';
export { NoSQLInjectionDetector } from './core/detectors/nosqli.js';
export { PrototypePollutionDetector } from './core/detectors/prototype-pollution.js';
export { SSRFDetector } from './core/detectors/ssrf.js';
export { XSSDetector } from './core/detectors/xss.js';
export { CommandInjectionDetector } from './core/detectors/command-injection.js';
export { PathTraversalDetector } from './core/detectors/path-traversal.js';
export { BotDetector } from './core/detectors/bot.js';
export { RateLimiter } from './core/rate-limiter.js';
export { IPFilter } from './core/ip-filter.js';
export { HoneypotTrap, DEFAULT_HONEYPOT_PATHS } from './core/honeypot.js';
export { ReputationEngine } from './core/reputation.js';
export { DefensiveTarpit } from './core/tarpit.js';
export { SevenLayerShield, DANGEROUS_HTTP_METHODS, STANDARD_ALLOWED_METHODS, } from './core/seven-layer-shield.js';
export type { SevenLayerConfig, ShieldLayerId, ShieldLayerResult, } from './core/seven-layer-shield.js';
export { MemoryStore } from './core/stores/memory-store.js';
export { RedisStore } from './core/stores/redis-store.js';
export { getSecurityHeaders } from './security/headers.js';
export { renderBlockedHtml, renderBlockedJson } from './templates/blocked-page.js';
export { ThreatForensicsCollector, parseDeviceFingerprint, extractGeoFromHeaders, } from './core/telemetry.js';
export type { ThreatForensicRecord, GeoLocation, ClientDeviceFingerprint, TelemetryConfig, } from './core/telemetry.js';
export { EndpointRegistry, normalizePath, makeEndpointId, } from './registry.js';
export type { EndpointRecord, RegistryStats } from './registry.js';
export { defineEndpointSecurity, mergeGuard, createGuardGroup, applyGuard, withGuard, guardExpress, } from './define.js';
export type { SecurityDefinition, GuardGroup, Platform } from './define.js';
export { ENDPOINT_PRESETS } from './presets.js';
export type { EndpointPresetKey } from './presets.js';
export * from './types.js';
//# sourceMappingURL=index.d.ts.map