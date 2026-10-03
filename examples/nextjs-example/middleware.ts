/**
 * Example Next.js Global Middleware (`middleware.ts`)
 * Protects all routes across the entire Next.js application.
 */

import { createNextGuardMiddleware } from 'nextguard';

export const middleware = createNextGuardMiddleware({
  mode: 'enforce', // 'enforce' to block attacks, or 'monitor' to only log without blocking

  // Anti-DDoS & Rate Limiting
  rateLimit: {
    windowMs: 60 * 1000, // 1 minute
    max: 100, // max 100 requests per minute per IP
    jailThreshold: 200, // Auto-jail DoS flooders
    jailDurationMs: 5 * 60 * 1000, // Jail IP for 5 minutes
  },

  // SQL Injection Protection
  sqlInjection: {
    enabled: true,
    sensitivity: 'medium', // 'low', 'medium', or 'high'
  },

  // Cross-Site Scripting (XSS) Protection
  xss: {
    enabled: true,
  },

  // Command Injection Protection
  commandInjection: {
    enabled: true,
  },

  // Path Traversal & LFI Protection
  pathTraversal: {
    enabled: true,
  },

  // Malicious Scanners & Bot Protection (e.g. sqlmap, nikto)
  badBots: {
    enabled: true,
    blockEmptyUserAgent: true,
  },

  // IP Filtering (Supports CIDR)
  ipFilter: {
    whitelist: ['127.0.0.1'],
    blacklist: ['198.51.100.1'],
  },

  // Exclude static assets from firewall checks
  excludePaths: [
    '/_next/*',
    '/favicon.ico',
    '/public/*',
  ],

  // Trigger webhooks or alerting on security blocks
  onBlocked: (verdict) => {
    console.warn(`[SECURITY ALERT] Blocked ${verdict.threatType} from IP: ${verdict.clientIp} (${verdict.reason})`);
  },
});

export const config = {
  // Apply firewall to all routes except Next.js internals
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
