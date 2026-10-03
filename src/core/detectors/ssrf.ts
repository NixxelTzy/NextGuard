/**
 * NextGuard - SSRF (Server-Side Request Forgery) Detector
 * Prevents attackers from targeting internal services, loopbacks, and cloud metadata APIs.
 */

import { SSRFConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';

const SSRF_PATTERNS: RegExp[] = [
  // Cloud metadata services (AWS, GCP, Azure, Alibaba)
  /https?:\/\/169\.254\.169\.254\b/i,
  /https?:\/\/metadata\.google\.internal\b/i,
  /https?:\/\/100\.100\.100\.200\b/i,

  // Loopback addresses
  /https?:\/\/127\.(?:\d{1,3}\.){2}\d{1,3}\b/i,
  /https?:\/\/localhost\b/i,
  /https?:\/\/0\.0\.0\.0(?::\d+|\/|$|\b)/i,
  /https?:\/\/\[::1\](?::\d+|\/|$)/i,
  /https?:\/\/0x7f000001\b/i, // hex encoded 127.0.0.1
  /https?:\/\/2130706433\b/i, // dword encoded 127.0.0.1

  // Private network ranges (RFC 1918)
  /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/i,
  /https?:\/\/172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b/i,
  /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}\b/i,

  // Dangerous non-HTTP schemes
  /(?:file|gopher|dict|ldap|tftp|sftp):\/\//i,
];

export class SSRFDetector {
  private patterns: RegExp[];

  constructor(config?: SSRFConfig) {
    this.patterns = [...SSRF_PATTERNS];
  }

  public detectValue(val: unknown, paramName?: string): DetectionResult {
    if (val === null || val === undefined) return { detected: false };
    if (typeof val === 'number' || typeof val === 'boolean') return { detected: false };

    if (typeof val === 'object') {
      return this.detectObject(val, paramName);
    }

    const str = String(val);
    let decoded = str;
    try {
      decoded = decodeURIComponent(str);
    } catch {}

    for (const pattern of this.patterns) {
      if (pattern.test(str) || pattern.test(decoded)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: str.length > 100 ? str.slice(0, 100) + '...' : str,
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
      const res = this.detectValue(value, currentParam);
      if (res.detected) return res;
    }

    return { detected: false };
  }
}
