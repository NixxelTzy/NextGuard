/**
 * NextGuard - Path Traversal & LFI/RFI Detector
 * Detects directory traversal attempts, null-byte poisoning, and unauthorized system file access.
 */
import { PathTraversalConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';
export declare class PathTraversalDetector {
    private patterns;
    constructor(config?: PathTraversalConfig);
    detectValue(val: unknown, paramName?: string): DetectionResult;
    detectObject(obj: unknown, prefix?: string): DetectionResult;
}
//# sourceMappingURL=path-traversal.d.ts.map