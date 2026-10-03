/**
 * NextGuard - SQL Injection Detector
 * Provides comprehensive pattern analysis and heuristic detection for SQL injection attacks.
 */
import { SQLiConfig } from '../../types.js';
export interface DetectionResult {
    detected: boolean;
    pattern?: string;
    matchedValue?: string;
    location?: string;
    parameter?: string;
}
export declare class SQLInjectionDetector {
    private patterns;
    private excludePatterns;
    private sensitivity;
    constructor(config?: SQLiConfig);
    /**
     * Check a single string value for SQL Injection signatures
     */
    detectValue(val: unknown, paramName?: string): DetectionResult;
    /**
     * Recursively inspect an object or array (e.g. query params, request body)
     */
    detectObject(obj: unknown, prefix?: string): DetectionResult;
}
//# sourceMappingURL=sqli.d.ts.map