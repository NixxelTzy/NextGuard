/**
 * NextGuard - OS Command Injection Detector
 * Detects command chaining, shell metacharacters, and unauthorized system command invocations.
 */
import { CommandInjectionConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';
export declare class CommandInjectionDetector {
    private patterns;
    constructor(config?: CommandInjectionConfig);
    detectValue(val: unknown, paramName?: string): DetectionResult;
    detectObject(obj: unknown, prefix?: string): DetectionResult;
}
//# sourceMappingURL=command-injection.d.ts.map