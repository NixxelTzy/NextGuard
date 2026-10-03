/**
 * NextGuard - SSRF (Server-Side Request Forgery) Detector
 * Prevents attackers from targeting internal services, loopbacks, and cloud metadata APIs.
 */
import { SSRFConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';
export declare class SSRFDetector {
    private patterns;
    constructor(config?: SSRFConfig);
    detectValue(val: unknown, paramName?: string): DetectionResult;
    detectObject(obj: unknown, prefix?: string): DetectionResult;
}
//# sourceMappingURL=ssrf.d.ts.map