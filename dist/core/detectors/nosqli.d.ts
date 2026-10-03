/**
 * NextGuard - NoSQL Injection Detector
 * Detects MongoDB, CouchDB, and NoSQL operator injections (e.g. $where, $gt, $ne, $regex).
 */
import { NoSQLiConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';
export declare class NoSQLInjectionDetector {
    private patterns;
    constructor(config?: NoSQLiConfig);
    detectValue(val: unknown, paramName?: string): DetectionResult;
    detectObject(obj: unknown, prefix?: string): DetectionResult;
}
//# sourceMappingURL=nosqli.d.ts.map