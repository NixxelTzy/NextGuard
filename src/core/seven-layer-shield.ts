/**
 * NextGuard - 7-Layer Defense-in-Depth Shield Architecture
 *
 * Implements a strict 7-layer defensive pipeline to intercept, neutralize,
 * and terminate exploitation attacks before they can touch application code.
 *
 * Layer 1: Network & IP Governance (Whitelist / Blacklist / CIDR Subnet)
 * Layer 2: HTTP Protocol Sanitization & Smuggling Defense (RFC Compliance, Verb filter, Header check)
 * Layer 3: Volumetric Anti-DDoS & Adaptive Suppression (Sliding Window, Burst Arrest, Auto-Jail)
 * Layer 4: Active Deception & Tripwire Honeypot (Quarantines scanner bots immediately)
 * Layer 5: Automated Scanner & Bot Defense (35+ scanner signatures, spoofed UA detection)
 * Layer 6: Deep Content & Multi-Vector Exploit Inspection (SQLi, NoSQLi, XSS, CMDi, LFI, ProtoPollution, SSRF)
 * Layer 7: Active Exploit Neutralizer & Crash Terminator (Connection reset, error injection to abort exploit runners)
 */

import { RequestContext, InspectionVerdict, ThreatType } from '../types.js';

export type ShieldLayerId =
  | 'L1_IP_GOVERNANCE'
  | 'L2_PROTOCOL_SANITIZER'
  | 'L3_DDOS_SUPPRESSION'
  | 'L4_HONEYPOT_DECEPTION'
  | 'L5_BOT_DEFENSE'
  | 'L6_DEEP_INSPECTION'
  | 'L7_EXPLOIT_NEUTRALIZER';

export interface ShieldLayerResult {
  passed: boolean;
  layer: ShieldLayerId;
  threatType?: ThreatType;
  reason?: string;
  statusCode?: number;
  location?: 'query' | 'body' | 'header' | 'url' | 'ip';
  parameter?: string;
  matchedPattern?: string;
  neutralized?: boolean;
}

export interface SevenLayerConfig {
  enabled?: boolean;
  /**
   * Action to take when an exploit is intercepted in Layer 7:
   * - 'abort_stream': Close/destroy TCP stream immediately (ECONNRESET to attacker)
   * - 'synthetic_error': Return a hard malformed error response to crash attacker script
   * - 'standard_block': Standard HTTP 403 Forbidden with security headers
   */
  neutralizeMode?: 'abort_stream' | 'synthetic_error' | 'standard_block';
  /**
   * Allowed HTTP methods (default: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
   */
  allowedMethods?: string[];
  /**
   * Maximum permitted HTTP header size in bytes (default: 16384 = 16KB)
   */
  maxHeaderSizeBytes?: number;
  /**
   * Disallow suspicious HTTP verbs often used in scanning (TRACE, TRACK, CONNECT, DEBUG)
   */
  blockDangerousMethods?: boolean;
}

export const DANGEROUS_HTTP_METHODS = new Set(['TRACE', 'TRACK', 'CONNECT', 'DEBUG', 'PUT_PROPFIND']);

export const STANDARD_ALLOWED_METHODS = new Set([
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'OPTIONS',
  'HEAD',
]);

export class SevenLayerShield {
  private config: SevenLayerConfig;
  private allowedMethods: Set<string>;
  private maxHeaderSize: number;

  constructor(config?: SevenLayerConfig) {
    this.config = config ?? {};
    this.allowedMethods = new Set(
      (config?.allowedMethods ?? Array.from(STANDARD_ALLOWED_METHODS)).map((m) => m.toUpperCase())
    );
    this.maxHeaderSize = config?.maxHeaderSizeBytes ?? 16384; // 16 KB
  }

  /**
   * Layer 2: HTTP Protocol & Request Sanitization
   * Checks for HTTP request smuggling, forbidden verbs, and header anomalies.
   */
  public inspectProtocol(req: RequestContext): ShieldLayerResult {
    const method = req.method.toUpperCase();

    // 1. Block dangerous methods (TRACE, TRACK, etc.)
    if (this.config.blockDangerousMethods !== false && DANGEROUS_HTTP_METHODS.has(method)) {
      return {
        passed: false,
        layer: 'L2_PROTOCOL_SANITIZER',
        threatType: 'suspicious_header',
        reason: `HTTP method ${method} is considered hazardous and blocked by Protocol Sanitizer`,
        statusCode: 405,
        location: 'header',
      };
    }

    // 2. Enforce allowed HTTP verbs
    if (!this.allowedMethods.has(method)) {
      return {
        passed: false,
        layer: 'L2_PROTOCOL_SANITIZER',
        threatType: 'suspicious_header',
        reason: `HTTP verb ${method} is not in allowed methods whitelist`,
        statusCode: 405,
        location: 'header',
      };
    }

    // 3. HTTP Request Smuggling Check: Conflicting Content-Length and Transfer-Encoding
    const headers = req.headers || {};
    const hasContentLength = 'content-length' in headers;
    const hasTransferEncoding = 'transfer-encoding' in headers;

    if (hasContentLength && hasTransferEncoding) {
      return {
        passed: false,
        layer: 'L2_PROTOCOL_SANITIZER',
        threatType: 'suspicious_header',
        reason: 'HTTP Request Smuggling anomaly detected: Conflicting Content-Length and Transfer-Encoding headers',
        statusCode: 400,
        location: 'header',
      };
    }

    // 4. Header Injection / Header Size Check
    let totalHeaderBytes = 0;
    for (const [key, value] of Object.entries(headers)) {
      const valStr = String(value || '');
      totalHeaderBytes += key.length + valStr.length;

      // Null byte injection in headers
      if (valStr.includes('\0') || key.includes('\0')) {
        return {
          passed: false,
          layer: 'L2_PROTOCOL_SANITIZER',
          threatType: 'suspicious_header',
          reason: 'Null byte injection detected in HTTP header',
          statusCode: 400,
          location: 'header',
          parameter: key,
        };
      }

      // CR/LF Header Splitting injection
      if (/[\r\n]/.test(valStr) || /[\r\n]/.test(key)) {
        return {
          passed: false,
          layer: 'L2_PROTOCOL_SANITIZER',
          threatType: 'suspicious_header',
          reason: 'CRLF injection (HTTP response splitting) detected in header',
          statusCode: 400,
          location: 'header',
          parameter: key,
        };
      }
    }

    if (totalHeaderBytes > this.maxHeaderSize) {
      return {
        passed: false,
        layer: 'L2_PROTOCOL_SANITIZER',
        threatType: 'payload_too_large',
        reason: `HTTP header size (${totalHeaderBytes} bytes) exceeded maximum threshold (${this.maxHeaderSize} bytes)`,
        statusCode: 431, // Request Header Fields Too Large
        location: 'header',
      };
    }

    return { passed: true, layer: 'L2_PROTOCOL_SANITIZER' };
  }

  /**
   * Layer 7: Active Exploit Neutralizer & Crash Response
   * Generates a terminating error payload that breaks the attacker's exploit script loop,
   * rendering the exploit harmless and instantly stopped.
   */
  public neutralizeExploit(verdict: InspectionVerdict): {
    statusCode: number;
    headers: Record<string, string>;
    body: string | Record<string, unknown>;
    shouldDestroySocket: boolean;
  } {
    const mode = this.config.neutralizeMode ?? 'synthetic_error';

    // Headers that terminate TCP reuse and prevent client caching
    const securityHeaders: Record<string, string> = {
      'Connection': 'close',
      'X-NextGuard-Shield': 'L7-Neutralized',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    };

    if (mode === 'abort_stream') {
      // Aborts the socket connection immediately (generates ECONNRESET on attacker client)
      return {
        statusCode: 400,
        headers: securityHeaders,
        body: 'ERR_CONNECTION_RESET_BY_NEXTGUARD_SHIELD',
        shouldDestroySocket: true,
      };
    }

    if (mode === 'synthetic_error') {
      // Returns a synthetic parser error specifically structured to trip automated attack runners
      return {
        statusCode: 400,
        headers: {
          ...securityHeaders,
          'Content-Type': 'application/json; charset=utf-8',
        },
        body: {
          error: 'ERR_EXPLOIT_PAYLOAD_NEUTRALIZED',
          status: 'attack_intercepted',
          layer: 'Layer_7_Exploit_Neutralizer',
          threat: verdict.threatType,
          reason: verdict.reason,
          code: 'E_EXPLOIT_ABORTED',
          message: 'The incoming exploit vector was intercepted and neutralized. Execution terminated immediately.',
          requestId: verdict.requestId,
          timestamp: verdict.timestamp,
        },
        shouldDestroySocket: false,
      };
    }

    // Standard block mode
    return {
      statusCode: verdict.statusCode || 403,
      headers: {
        ...securityHeaders,
        'Content-Type': 'application/json; charset=utf-8',
      },
      body: {
        success: false,
        error: 'Access Denied by NextGuard Shield',
        code: 'FIREWALL_BLOCKED',
        threat: verdict.threatType,
        reason: verdict.reason,
        clientIp: verdict.clientIp,
        requestId: verdict.requestId,
        timestamp: verdict.timestamp,
      },
      shouldDestroySocket: false,
    };
  }

  /**
   * De-weaponize input: neutralizes dangerous shell, SQL, or script tokens
   * so they cause runtime syntax errors in attacker scripts rather than execution.
   */
  public deweaponizeString(input: string): string {
    return input
      .replace(/(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b)/gi, '[BLOCKED_$1]')
      .replace(/(\bexec\b|\beval\b|\bsystem\b|\bpassthru\b)/gi, '[NEUTRALIZED_$1]')
      .replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gi, '[NEUTRALIZED_SCRIPT]')
      .replace(/(\.\.\/|\.\.\\)/g, '[NEUTRALIZED_PATH]');
  }
}
