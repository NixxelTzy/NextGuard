/**
 * NextGuard - Core Security Engine
 * Orchestrates all detection modules, rate limiting, and rule enforcement.
 */
import { NextGuardConfig, RequestContext, InspectionVerdict } from '../types.js';
import { RateLimiter } from './rate-limiter.js';
import { IPFilter } from './ip-filter.js';
import { HoneypotTrap } from './honeypot.js';
import { ReputationEngine } from './reputation.js';
import { DefensiveTarpit } from './tarpit.js';
export declare class NextGuardEngine {
    private config;
    private sqliDetector;
    private nosqliDetector;
    private protoDetector;
    private ssrfDetector;
    private xssDetector;
    private cmdDetector;
    private pathDetector;
    private botDetector;
    private rateLimiter;
    private ipFilter;
    private honeypot;
    private reputation;
    private tarpit;
    constructor(config?: NextGuardConfig);
    /**
     * Find matching endpoint override if defined in config.endpoints
     */
    private getEndpointOverride;
    /**
     * Main inspection method that verifies every incoming request against all firewall rules
     */
    inspect(req: RequestContext): Promise<InspectionVerdict>;
    private handleVerdict;
    getRateLimiter(): RateLimiter;
    getIPFilter(): IPFilter;
    getReputation(): ReputationEngine;
    getHoneypot(): HoneypotTrap;
    getTarpit(): DefensiveTarpit;
}
//# sourceMappingURL=engine.d.ts.map