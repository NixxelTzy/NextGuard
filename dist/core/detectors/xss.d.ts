/**
 * NextGuard - Cross-Site Scripting (XSS) Detector
 * Detects reflected, stored, and DOM-based XSS payloads across queries, bodies, and headers.
 */
import { XSSConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';
export declare class XSSDetector {
    private patterns;
    private excludePatterns;
    private sensitivity;
    constructor(config?: XSSConfig);
    detectValue(val: unknown, paramName?: string): DetectionResult;
    detectObject(obj: unknown, prefix?: string): DetectionResult;
}
//# sourceMappingURL=xss.d.ts.map