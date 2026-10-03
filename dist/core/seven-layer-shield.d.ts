/**
 * NextGuard - 7-Layer Defense-in-Depth Shield Architecture
 *
 * Implements a strict 7-layer defensive pipeline to intercept, neutralize,
 * and terminate exploitation attacks before they can touch application code.
 *
 * Layer 1: Network & IP Governance (Whitelist / Blacklist / CIDR Subnet)
 * Layer 2: HTTP Protocol Sanitization & Smuggling Defense (RFC Compliance, Verb filter, Header check)
 * Layer 3: Volumetric Anti-DDoS & Adaptive Suppression (Sliding Window, Burst Arrest, Auto-Jail)
 * Layer 4: Active Deception & Tripwire Honeypot (Quarantines scanner bots immediately)
 * Layer 5: Automated Scanner & Bot Defense (35+ scanner signatures, spoofed UA detection)
 * Layer 6: Deep Content & Multi-Vector Exploit Inspection (SQLi, NoSQLi, XSS, CMDi, LFI, ProtoPollution, SSRF)
 * Layer 7: Active Exploit Neutralizer & Crash Terminator (Connection reset, error injection to abort exploit runners)
 */
import { RequestContext, InspectionVerdict, ThreatType } from '../types.js';
export type ShieldLayerId = 'L1_IP_GOVERNANCE' | 'L2_PROTOCOL_SANITIZER' | 'L3_DDOS_SUPPRESSION' | 'L4_HONEYPOT_DECEPTION' | 'L5_BOT_DEFENSE' | 'L6_DEEP_INSPECTION' | 'L7_EXPLOIT_NEUTRALIZER';
export interface ShieldLayerResult {
    passed: boolean;
    layer: ShieldLayerId;
    threatType?: ThreatType;
    reason?: string;
    statusCode?: number;
    location?: 'query' | 'body' | 'header' | 'url' | 'ip';
    parameter?: string;
    matchedPattern?: string;
    neutralized?: boolean;
}
export interface SevenLayerConfig {
    enabled?: boolean;
    /**
     * Action to take when an exploit is intercepted in Layer 7:
     * - 'abort_stream': Close/destroy TCP stream immediately (ECONNRESET to attacker)
     * - 'synthetic_error': Return a hard malformed error response to crash attacker script
     * - 'standard_block': Standard HTTP 403 Forbidden with security headers
     */
    neutralizeMode?: 'abort_stream' | 'synthetic_error' | 'standard_block';
    /**
     * Allowed HTTP methods (default: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
     */
    allowedMethods?: string[];
    /**
     * Maximum permitted HTTP header size in bytes (default: 16384 = 16KB)
     */
    maxHeaderSizeBytes?: number;
    /**
     * Disallow suspicious HTTP verbs often used in scanning (TRACE, TRACK, CONNECT, DEBUG)
     */
    blockDangerousMethods?: boolean;
}
export declare const DANGEROUS_HTTP_METHODS: Set<string>;
export declare const STANDARD_ALLOWED_METHODS: Set<string>;
export declare class SevenLayerShield {
    private config;
    private allowedMethods;
    private maxHeaderSize;
    constructor(config?: SevenLayerConfig);
    /**
     * Layer 2: HTTP Protocol & Request Sanitization
     * Checks for HTTP request smuggling, forbidden verbs, and header anomalies.
     */
    inspectProtocol(req: RequestContext): ShieldLayerResult;
    /**
     * Layer 7: Active Exploit Neutralizer & Crash Response
     * Generates a terminating error payload that breaks the attacker's exploit script loop,
     * rendering the exploit harmless and instantly stopped.
     */
    neutralizeExploit(verdict: InspectionVerdict): {
        statusCode: number;
        headers: Record<string, string>;
        body: string | Record<string, unknown>;
        shouldDestroySocket: boolean;
    };
    /**
     * De-weaponize input: neutralizes dangerous shell, SQL, or script tokens
     * so they cause runtime syntax errors in attacker scripts rather than execution.
     */
    deweaponizeString(input: string): string;
}
//# sourceMappingURL=seven-layer-shield.d.ts.map