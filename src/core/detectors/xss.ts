/**
 * NextGuard - Cross-Site Scripting (XSS) Detector
 * Detects reflected, stored, and DOM-based XSS payloads across queries, bodies, and headers.
 */

import { XSSConfig, SensitivityLevel } from '../../types.js';
import { DetectionResult } from './sqli.js';

const XSS_PATTERNS = {
  // Direct script tags
  scriptTag: [
    /<\s*script\b[^>]*>[\s\S]*?(?:<\/\s*script\s*>)?/i,
    /<\s*\/\s*script\s*>/i,
    /<\s*script\b/i,
  ],

  // Inline DOM event handlers (e.g. onload, onerror, onclick, onmouseover)
  eventHandlers: [
    /\bon(?:load|error|click|dblclick|mouseover|mouseout|mouseenter|mouseleave|mousemove|keydown|keyup|keypress|focus|blur|change|submit|reset|input|contextmenu|drag|drop|scroll|wheel|toggle|pointerdown|pointerup)\s*=\s*['"]?[^'"]*['"]?/i,
    /<[^>]+\bon[a-z]+\s*=/i,
  ],

  // Javascript / VBScript / Data URIs in src, href, or attributes
  uriProtocols: [
    /(?:href|src|data|action|formaction)\s*=\s*['"]?\s*javascript\s*:/i,
    /(?:href|src|data|action|formaction)\s*=\s*['"]?\s*vbscript\s*:/i,
    /(?:href|src|data|action|formaction)\s*=\s*['"]?\s*data:\s*text\/html/i,
    /\bdata:\s*text\/html/i,
    /javascript\s*:\s*[^\s]+/i,
  ],

  // Dangerous HTML tags typically used for injection: <iframe>, <object>, <embed>, <svg onload>, <img> with onerror
  dangerousTags: [
    /<\s*(?:iframe|object|embed|applet|meta|base|link|form)\b[^>]*>/i,
    /<\s*svg\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*img\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*body\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*audio\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*video\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*style\b[^>]*>[\s\S]*?(?:expression\(|behavior:|url\s*\(\s*['"]?javascript:)/i,
  ],

  // JS execution primitives commonly used in evasion
  executionPrimitives: [
    /(?:window|document|top|parent)\s*\[\s*['"][a-z]+['"]\s*\]/i,
    /document\s*\.\s*(?:cookie|location|write|writeln|domain)\b/i,
    /window\s*\.\s*(?:location|eval)\b/i,
    /(?:\beval\b|\bFunction\b|\bsetTimeout\b|\bsetInterval\b)\s*\(\s*['"][^'"]*['"]\s*\)/i,
  ],
};

function decodeHtmlEntities(str: string): string {
  return str
    .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);?/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&amp;/gi, '&');
}

function safeUrlDecode(value: string): string {
  try {
    const once = decodeURIComponent(value);
    try {
      return decodeURIComponent(once);
    } catch {
      return once;
    }
  } catch {
    return value;
  }
}

export class XSSDetector {
  private patterns: RegExp[] = [];
  private excludePatterns: RegExp[] = [];
  private sensitivity: SensitivityLevel = 'medium';

  constructor(config?: XSSConfig) {
    this.sensitivity = config?.sensitivity || 'medium';
    this.excludePatterns = config?.excludePatterns || [];

    // Core patterns
    this.patterns.push(
      ...XSS_PATTERNS.scriptTag,
      ...XSS_PATTERNS.eventHandlers,
      ...XSS_PATTERNS.uriProtocols
    );

    // Medium sensitivity
    if (this.sensitivity === 'medium' || this.sensitivity === 'high') {
      this.patterns.push(...XSS_PATTERNS.dangerousTags);
    }

    // High sensitivity
    if (this.sensitivity === 'high') {
      this.patterns.push(...XSS_PATTERNS.executionPrimitives);
    }

    if (config?.customPatterns && config.customPatterns.length > 0) {
      this.patterns.push(...config.customPatterns);
    }
  }

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
      return this.detectObject(val, paramName);
    } else {
      stringVal = String(val);
    }

    for (const exclude of this.excludePatterns) {
      if (exclude.test(stringVal)) {
        return { detected: false };
      }
    }

    const decodedUrl = safeUrlDecode(stringVal);
    const decodedHtml = decodeHtmlEntities(decodedUrl);

    for (const pattern of this.patterns) {
      if (pattern.test(stringVal) || pattern.test(decodedUrl) || pattern.test(decodedHtml)) {
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
