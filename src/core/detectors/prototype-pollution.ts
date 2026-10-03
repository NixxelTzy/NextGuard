/**
 * NextGuard - Prototype Pollution Detector
 * Prevents object prototype tampering in Node.js applications (e.g. __proto__, constructor.prototype).
 */

import { PrototypePollutionConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';

const POLLUTION_KEYS: RegExp[] = [
  /(?:^|\.)__proto__(?:\.|$|\[)/,
  /(?:^|\.)constructor\.prototype(?:\.|$|\[)/,
  /(?:^|\.)prototype(?:\.|$|\[)/,
  /__defineGetter__/,
  /__defineSetter__/,
  /__lookupGetter__/,
  /__lookupSetter__/,
];

export class PrototypePollutionDetector {
  constructor(_config?: PrototypePollutionConfig) {}

  public detectValue(val: unknown, paramName?: string): DetectionResult {
    if (val === null || val === undefined) return { detected: false };

    if (typeof val === 'object') {
      return this.detectObject(val, paramName);
    }

    const str = String(val);
    for (const pattern of POLLUTION_KEYS) {
      if (pattern.test(str)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: str,
          parameter: paramName,
        };
      }
    }

    return { detected: false };
  }

  public detectObject(obj: unknown, prefix = ''): DetectionResult {
    if (!obj || typeof obj !== 'object') {
      return this.detectValue(obj, prefix);
    }

    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const res = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (res.detected) return res;
      }
      return { detected: false };
    }

    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;

      // Check key directly
      for (const pattern of POLLUTION_KEYS) {
        if (pattern.test(key) || pattern.test(currentParam)) {
          return {
            detected: true,
            pattern: pattern.toString(),
            matchedValue: key,
            parameter: currentParam,
            location: 'parameter_key',
          };
        }
      }

      const res = this.detectValue(value, currentParam);
      if (res.detected) return res;
    }

    return { detected: false };
  }
}
