/**
 * NextGuard - OS Command Injection Detector
 * Detects command chaining, shell metacharacters, and unauthorized system command invocations.
 */

import { CommandInjectionConfig } from '../../types.js';
import { DetectionResult } from './sqli.js';

const COMMAND_INJECTION_PATTERNS = [
  // Command chaining with common recon/malicious commands
  /(?:[;&|`]\s*(?:cat|more|less|tail|head)\s+(?:\/etc\/|\/var\/|\/tmp\/|[a-zA-Z]:\\))/i,
  /(?:[;&|`]\s*(?:id|whoami|uname\s+-a|hostname|ifconfig|ip\s+a)\b)/i,
  /(?:[;&|`]\s*(?:curl|wget|nc|ncat|netcat|bash|sh|zsh|csh)\s+)/i,
  /(?:[;&|`]\s*(?:rm\s+-rf|chmod\s+[0-7]{3,4}|chown\s+))/i,
  /(?:[;&|`]\s*(?:powershell(?:\.exe)?|cmd(?:\.exe)?)\b)/i,
  /(?:[;&|`]\s*(?:systeminfo|net\s+user|net\s+localgroup)\b)/i,

  // Shell substitution syntax
  /\$\(\s*(?:cat|id|whoami|uname|ls|dir|curl|wget|bash|sh|powershell)\b/i,
  /`\s*(?:cat|id|whoami|uname|ls|dir|curl|wget|bash|sh|powershell)\b/i,

  // Direct reverse shell signatures
  /\/bin\/(?:ba)?sh\s+-i/i,
  /\bnc(?:\.traditional)?\s+.*?-e\s+\S+/i,
  /\bnc\s+(?:-[a-zA-Z]*e\s+)?(?:\d{1,3}\.){3}\d{1,3}\s+\d+/i,
  /bash\s+-c\s+['"].*?>&/i,

  // Windows command injection patterns
  /(?:&|&&|\||\|\|)\s*(?:dir|type|copy|del|tasklist|reg\s+query)\b/i,
];

export class CommandInjectionDetector {
  private patterns: RegExp[] = [];

  constructor(config?: CommandInjectionConfig) {
    this.patterns = [...COMMAND_INJECTION_PATTERNS];
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
