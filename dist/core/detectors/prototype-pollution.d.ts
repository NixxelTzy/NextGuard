/**
 * NextGuard - Prototype Pollution Detector
 * Prevents object prototype tampering in Node.js applications (e.g. __proto__, constructor.prototype).
 */
import { PrototypePollutionConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';
export declare class PrototypePollutionDetector {
    constructor(_config?: PrototypePollutionConfig);
    detectValue(val: unknown, paramName?: string): DetectionResult;
    detectObject(obj: unknown, prefix?: string): DetectionResult;
}
//# sourceMappingURL=prototype-pollution.d.ts.map