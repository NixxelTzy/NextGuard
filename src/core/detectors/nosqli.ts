/**
 * NextGuard - NoSQL Injection Detector
 * Detects MongoDB, CouchDB, and NoSQL operator injections (e.g. $where, $gt, $ne, $regex).
 */

import { NoSQLiConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';

const NOSQL_OPERATOR_PATTERNS: RegExp[] = [
  /^\$(?:where|regex|ne|gt|gte|lt|lte|in|nin|exists|type|mod|all|size|elemMatch|expr|jsonSchema|text|search|or|and|nor|not)\b/i,
  /["']\$(?:where|regex|ne|gt|gte|lt|lte|in|nin|exists|type|mod|all|size|elemMatch|expr|or|and|nor|not)["']\s*:/i,
  /\btojson\s*\(/i,
  /\bmapreduce\s*\(/i,
  /\bdb\.\w+\.(?:find|update|insert|remove|drop)\b/i,
];

export class NoSQLInjectionDetector {
  private patterns: RegExp[];

  constructor(config?: NoSQLiConfig) {
    this.patterns = [...NOSQL_OPERATOR_PATTERNS];
    if (config?.customPatterns) {
      this.patterns.push(...config.customPatterns);
    }
  }

  public detectValue(val: unknown, paramName?: string): DetectionResult {
    if (val === null || val === undefined) return { detected: false };
    if (typeof val === 'number' || typeof val === 'boolean') return { detected: false };

    if (typeof val === 'object') {
      return this.detectObject(val, paramName);
    }

    const stringVal = String(val);

    for (const pattern of this.patterns) {
      if (pattern.test(stringVal)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: stringVal.length > 100 ? stringVal.slice(0, 100) + '...' : stringVal,
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

      // Check key itself (e.g. { "$gt": "" } or { "$where": "..." })
      if (key.startsWith('$')) {
        for (const pattern of this.patterns) {
          if (pattern.test(key)) {
            return {
              detected: true,
              pattern: pattern.toString(),
              matchedValue: key,
              parameter: currentParam,
              location: 'parameter_key',
            };
          }
        }
      }

      const res = this.detectValue(value, currentParam);
      if (res.detected) return res;
    }

    return { detected: false };
  }
}
