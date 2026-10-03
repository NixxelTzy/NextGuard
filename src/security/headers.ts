/**
 * NextGuard - Security Headers Generator
 * Implements OWASP recommended HTTP response security headers.
 */

import { SecurityHeadersConfig } from '../types.js';

export function getSecurityHeaders(config?: SecurityHeadersConfig | boolean): Record<string, string> {
  if (config === false) return {};

  const cfg = typeof config === 'object' ? config : {};
  if (cfg.enabled === false) return {};

  const headers: Record<string, string> = {};

  // X-Content-Type-Options: nosniff
  if (cfg.xContentTypeOptions !== false) {
    headers['X-Content-Type-Options'] = 'nosniff';
  }

  // X-Frame-Options
  if (cfg.xFrameOptions !== false) {
    headers['X-Frame-Options'] = cfg.xFrameOptions || 'DENY';
  }

  // X-XSS-Protection
  if (cfg.xXSSProtection !== false) {
    headers['X-XSS-Protection'] = cfg.xXSSProtection || '0'; // Modern best practice: disable legacy buggy auditor
  }

  // Referrer-Policy
  if (cfg.referrerPolicy !== false) {
    headers['Referrer-Policy'] = cfg.referrerPolicy || 'strict-origin-when-cross-origin';
  }

  // Strict-Transport-Security (HSTS)
  if (cfg.strictTransportSecurity !== false) {
    headers['Strict-Transport-Security'] =
      typeof cfg.strictTransportSecurity === 'string'
        ? cfg.strictTransportSecurity
        : 'max-age=31536000; includeSubDomains; preload';
  }

  // Permissions-Policy
  if (cfg.permissionsPolicy !== false) {
    headers['Permissions-Policy'] =
      typeof cfg.permissionsPolicy === 'string'
        ? cfg.permissionsPolicy
        : 'camera=(), microphone=(), geolocation=(), interest-cohort=()';
  }

  // Content-Security-Policy
  if (cfg.contentSecurityPolicy) {
    headers['Content-Security-Policy'] = cfg.contentSecurityPolicy;
  }

  return headers;
}
