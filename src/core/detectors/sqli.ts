/**
 * NextGuard - SQL Injection Detector
 * Provides comprehensive pattern analysis and heuristic detection for SQL injection attacks.
 */

import { SQLiConfig, SensitivityLevel } from '../../types.js';

export interface DetectionResult {
  detected: boolean;
  pattern?: string;
  matchedValue?: string;
  location?: string;
  parameter?: string;
}

// Regex patterns categorized by threat vector
const SQLI_PATTERNS = {
  // Boolean-based and tautology attacks: ' OR 1=1, " OR ""=", ' OR 'x'='x
  tautology: [
    /(?:['"]\s*or\s+['"\d\w]+\s*=\s*['"\d\w]+)/i,
    /(?:["']\s*or\s+true\s*--?)/i,
    /(?:\bor\b\s+[\w\d]+\s*=\s*[\w\d]+)/i,
    /(?:\band\b\s+[\w\d]+\s*!=\s*[\w\d]+)/i,
    /(?:\b(?:or|and)\b\s+1\s*=\s*1)/i,
    /(?:\b(?:or|and)\b\s+0\s*=\s*0)/i,
    /(?:\b(?:or|and)\b\s+['"]?1['"]?\s*=\s*['"]?1['"]?)/i,
    /(?:admin['"]\s*(?:--|#|\/\*))/i,
    /(?:['"]\s*or\s*['"]{1,2}\s*=\s*['"]?)/i,
    /(?:['"]\s*or\s*''\s*=\s*')/i,
    /(?:["']\s*or\s*""\s*=\s*")/i,
  ],

  // UNION-based attacks: UNION SELECT, UNION ALL SELECT
  union: [
    /(?:\bunion\b(?:\s+all)?\s+\bselect\b)/i,
    /(?:\bunion\b\s+.*?\bselect\b)/i,
    /(?:\bselect\b\s+.*?\bfrom\b\s+.*?\bunion\b)/i,
  ],

  // Stacked queries and destructive commands
  destructive: [
    /(?:;\s*(?:drop|truncate|alter|create)\s+(?:table|database|view|index|schema)\b)/i,
    /(?:;\s*(?:insert\s+into|update\s+\w+\s+set|delete\s+from)\b)/i,
    /(?:;\s*shutdown\b)/i,
    /(?:;\s*exec\s+(?:xp_cmdshell|sp_executesql)\b)/i,
  ],

  // Time-based blind SQLi functions
  timeBased: [
    /(?:\bsleep\s*\(\s*\d+\s*\))/i,
    /(?:\bbenchmark\s*\(\s*\d+\s*,.*?\))/i,
    /(?:\bwaitfor\s+delay\s+['"]\d+:\d+:\d+['"])/i,
    /(?:\bpg_sleep\s*\(\s*\d+\s*\))/i,
    /(?:\bdbms_pipe\.receive_message\b)/i,
  ],

  // Information schema & database metadata harvesting
  schemaExtraction: [
    /(?:\binformation_schema\.(?:tables|columns|schemata|views|user_privileges)\b)/i,
    /(?:\bsys\.(?:tables|databases|all_views)\b)/i,
    /(?:\bsqlite_master\b)/i,
    /(?:\ball_tab_columns\b)/i,
    /(?:\bpg_catalog\b)/i,
    /(?:\bload_file\s*\(.*?\))/i,
    /(?:\binto\s+(?:outfile|dumpfile)\b)/i,
  ],

  // Comments and inline obfuscation
  commentsAndSyntax: [
    /(?:(?:\/\*![\d]*|\/\*)[^*]*\*+(?:[^*\/][^*]*\*+)*\/)/i, // /*!50000 SELECT */ or multi-line comment tricks
    /(?:'\s*--)/i,
    /(?:;\s*--)/i,
    /(?:'\s*#)/i,
    /(?:'\s*\/\*)/i,
  ],

  // High-sensitivity patterns (heuristic)
  highSensitivity: [
    /(?:\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*)*\))/i,
    /(?:\bconcat\s*\(.*?\bselect\b)/i,
    /(?:\bextractvalue\s*\(.*?\))/i,
    /(?:\bupdatexml\s*\(.*?\))/i,
    /(?:\bxp_cmdshell\b)/i,
    /(?:0x[0-9a-fA-F]{6,})/i, // long hex literals
    /(?:\bcast\s*\(.*?\bas\s+(?:char|varchar|integer)\b)/i,
    /(?:\bconvert\s*\(.*?\busing\b)/i,
  ],
};

function safeUrlDecode(value: string): string {
  try {
    const once = decodeURIComponent(value);
    // Double decoding attempt to catch double-encoded bypass attacks (%2527 -> %27 -> ')
    try {
      return decodeURIComponent(once);
    } catch {
      return once;
    }
  } catch {
    return value;
  }
}

/**
 * Normalizes input string to remove evasion tactics:
 * - Decodes URL encoding
 * - Normalizes inline SQL comment separators (e.g. UN[comment]ION -> UNION)
 * - Normalizes excessive whitespace
 */
function normalizeString(input: string): string {
  let normalized = safeUrlDecode(input);
  // Remove null bytes
  normalized = normalized.replace(/\0/g, '');
  // Normalize comment evasion tricks like SEL/**/ECT
  normalized = normalized.replace(/\/\*.*?\*\//g, ' ');
  // Normalize whitespace
  normalized = normalized.replace(/\s+/g, ' ').trim();
  return normalized;
}

export class SQLInjectionDetector {
  private patterns: RegExp[] = [];
  private excludePatterns: RegExp[] = [];
  private sensitivity: SensitivityLevel = 'medium';

  constructor(config?: SQLiConfig) {
    this.sensitivity = config?.sensitivity || 'medium';
    this.excludePatterns = config?.excludePatterns || [];

    // Core patterns included in all sensitivity levels
    this.patterns.push(
      ...SQLI_PATTERNS.tautology,
      ...SQLI_PATTERNS.union,
      ...SQLI_PATTERNS.destructive,
      ...SQLI_PATTERNS.timeBased
    );

    // Medium sensitivity adds schema extraction & comments
    if (this.sensitivity === 'medium' || this.sensitivity === 'high') {
      this.patterns.push(
        ...SQLI_PATTERNS.schemaExtraction,
        ...SQLI_PATTERNS.commentsAndSyntax
      );
    }

    // High sensitivity adds edge-case / blind heuristics
    if (this.sensitivity === 'high') {
      this.patterns.push(...SQLI_PATTERNS.highSensitivity);
    }

    // Custom user-defined patterns
    if (config?.customPatterns && config.customPatterns.length > 0) {
      this.patterns.push(...config.customPatterns);
    }
  }

  /**
   * Check a single string value for SQL Injection signatures
   */
  public detectValue(val: unknown, paramName?: string): DetectionResult {
    if (val === null || val === undefined) {
      return { detected: false };
    }

    if (typeof val === 'number' || typeof val === 'boolean') {
      return { detected: false };
    }

    let stringVal = '';
    if (typeof val === 'string') {
      stringVal = val;
    } else if (typeof val === 'object') {
      // Recursively check objects/arrays
      return this.detectObject(val, paramName);
    } else {
      stringVal = String(val);
    }

    // Check user exclusion patterns first
    for (const exclude of this.excludePatterns) {
      if (exclude.test(stringVal)) {
        return { detected: false };
      }
    }

    const normalized = normalizeString(stringVal);

    for (const pattern of this.patterns) {
      if (pattern.test(stringVal) || pattern.test(normalized)) {
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

  /**
   * Recursively inspect an object or array (e.g. query params, request body)
   */
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
      // Also inspect parameter keys themselves (e.g. ?id' OR 1=1--=val)
      const keyResult = this.detectValue(key, currentParam);
      if (keyResult.detected) {
        return { ...keyResult, location: 'parameter_key' };
      }

      const valResult = this.detectValue(value, currentParam);
      if (valResult.detected) {
        return valResult;
      }
    }

    return { detected: false };
  }
}
