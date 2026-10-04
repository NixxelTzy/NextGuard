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
export class NextGuard {
  private engine: NextGuardEngine;
  private config: NextGuardConfig;

  constructor(config: NextGuardConfig = {}) {
    this.config = config;
    this.engine = new NextGuardEngine(config);
  }

  /**
   * Inspect a request context and return the firewall verdict
   */
  public async inspect(req: RequestContext): Promise<InspectionVerdict> {
    return this.engine.inspect(req);
  }

  /**
   * Create Next.js global middleware (`middleware.ts`)
   */
  public nextMiddleware(overrideConfig?: NextGuardConfig) {
    return createNextGuardMiddleware({ ...this.config, ...overrideConfig });
  }

  /**
   * Protect Next.js App Router route handler (app/api/.../route.ts)
   */
  public protectAppRoute(
    handler: Parameters<typeof withNextGuard>[0],
    overrideConfig?: NextGuardConfig
  ) {
    return withNextGuard(handler, { ...this.config, ...overrideConfig });
  }

  /**
   * Protect Next.js Pages Router API handler (pages/api/...ts)
   */
  public protectPagesRoute(
    handler: Parameters<typeof withNextGuardPages>[0],
    overrideConfig?: NextGuardConfig
  ) {
    return withNextGuardPages(handler, { ...this.config, ...overrideConfig });
  }

  /**
   * Node.js Express / Connect middleware
   */
  public express(overrideConfig?: NextGuardConfig) {
    return nextGuardExpress({ ...this.config, ...overrideConfig });
  }

  /**
   * Get underlying engine
   */
  public getEngine(): NextGuardEngine {
    return this.engine;
  }
}

// Default export & Named exports
export default NextGuard;

export {
  NextGuardEngine,
  createNextGuardMiddleware,
  withNextGuard,
  withNextGuardPages,
  nextGuardExpress,
};

// Core Detectors & Engines
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
export {
  SevenLayerShield,
  DANGEROUS_HTTP_METHODS,
  STANDARD_ALLOWED_METHODS,
} from './core/seven-layer-shield.js';
export type {
  SevenLayerConfig,
  ShieldLayerId,
  ShieldLayerResult,
} from './core/seven-layer-shield.js';

// Storage Engines
export { MemoryStore } from './core/stores/memory-store.js';
export { RedisStore } from './core/stores/redis-store.js';

// Security Headers & Block Page
export { getSecurityHeaders } from './security/headers.js';
export { renderBlockedHtml, renderBlockedJson } from './templates/blocked-page.js';

// Threat Forensics, Geolocation & Device Telemetry
export {
  ThreatForensicsCollector,
  parseDeviceFingerprint,
  extractGeoFromHeaders,
} from './core/telemetry.js';
export type {
  ThreatForensicRecord,
  GeoLocation,
  ClientDeviceFingerprint,
  TelemetryConfig,
} from './core/telemetry.js';

// Endpoint Registry (auto-discovery dari traffic aktual)
export {
  EndpointRegistry,
  normalizePath,
  makeEndpointId,
} from './registry.js';
export type { EndpointRecord, RegistryStats } from './registry.js';

// Security Definition API (untuk user mendefinisikan security di proyek mereka)
export {
  defineEndpointSecurity,
  mergeGuard,
  createGuardGroup,
  applyGuard,
  withGuard,
  guardExpress,
} from './define.js';
export type { SecurityDefinition, GuardGroup, Platform } from './define.js';

// Endpoint Presets
export { ENDPOINT_PRESETS } from './presets.js';
export type { EndpointPresetKey } from './presets.js';

// Database Guard (per-route database protection)
export { DatabaseGuard, createDatabaseGuard } from './core/database-guard.js';
export type { DatabaseGuardConfig, DatabaseGuardResult } from './core/database-guard.js';

// All Types
export * from './types.js';
