/**
 * NextGuard - Path Traversal & LFI/RFI Detector
 * Detects directory traversal attempts, null-byte poisoning, and unauthorized system file access.
 */

import { PathTraversalConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';

const PATH_TRAVERSAL_PATTERNS = [
  // Directory traversal sequences (plain, url encoded, double url encoded)
  /(?:\.\.\/|\.\.\\)/,
  /(?:%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|\.\.%5c)/i,
  /(?:%252e%252e%252f|%252e%252e\/)/i,

  // Common sensitive files (Unix/Linux)
  /(?:\/etc\/(?:passwd|shadow|hosts|group|issue|hostname|crontab))/i,
  /(?:\/proc\/(?:self|version|cmdline|environ|net\/tcp))/i,
  /(?:\/var\/log\/(?:apache2|nginx|syslog|auth\.log|messages))/i,

  // Common sensitive files (Windows)
  /(?:[a-zA-Z]:\\(?:windows|winnt)\\(?:system32|repair|win\.ini|system\.ini))/i,
  /(?:boot\.ini|pagefile\.sys)/i,

  // Null byte injection attempt
  /(?:%00|\0)/,

  // PHP wrapper and remote file inclusion schemes
  /(?:php:\/\/(?:input|filter|memory|temp)|data:\/\/text\/plain|expect:\/\/)/i,
];

export class PathTraversalDetector {
  private patterns: RegExp[] = [];

  constructor(config?: PathTraversalConfig) {
    this.patterns = [...PATH_TRAVERSAL_PATTERNS];
    if (config?.customPatterns) {
      this.patterns.push(...config.customPatterns);
    }
  }

  public detectValue(val: unknown, paramName?: string): DetectionResult {
    if (val === null || val === undefined) return { detected: false };
    if (typeof val === 'number' || typeof val === 'boolean') return { detected: false };

    let stringVal = '';
    if (typeof val === 'string') {
      stringVal = val;
    } else if (typeof val === 'object') {
      return this.detectObject(val, paramName);
    } else {
      stringVal = String(val);
    }

    let decoded = stringVal;
    try {
      decoded = decodeURIComponent(stringVal);
    } catch {
      // Ignore decode error
    }

    for (const pattern of this.patterns) {
      if (pattern.test(stringVal) || pattern.test(decoded)) {
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
        const result = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (result.detected) return result;
      }
      return { detected: false };
    }

    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      const keyResult = this.detectValue(key, currentParam);
      if (keyResult.detected) return { ...keyResult, location: 'parameter_key' };

      const valResult = this.detectValue(value, currentParam);
      if (valResult.detected) return valResult;
    }

    return { detected: false };
  }
}
