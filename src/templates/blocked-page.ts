/**
 * NextGuard - Security Block Page & Error Templates
 * Produces modern, sleek HTML challenge/blocked pages and structured JSON responses.
 */

import { InspectionVerdict } from '../types.js';

export function renderBlockedJson(verdict: InspectionVerdict): Record<string, unknown> {
  return {
    success: false,
    error: 'Access Denied by NextGuard Firewall',
    code: 'FIREWALL_BLOCKED',
    threat: verdict.threatType,
    reason: verdict.reason,
    clientIp: verdict.clientIp,
    requestId: verdict.requestId,
    timestamp: new Date(verdict.timestamp).toISOString(),
  };
}

export function renderBlockedHtml(verdict: InspectionVerdict): string {
  const threatTitle = formatThreatTitle(verdict.threatType);
  const dateFormatted = new Date(verdict.timestamp).toUTCString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 Forbidden - NextGuard Security</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #0b0f19;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: #151c2c;
      border: 1px solid #2d3748;
      border-radius: 12px;
      max-width: 600px;
      width: 100%;
      padding: 2.5rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }
    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 1.5rem;
    }
    .shield-icon {
      width: 44px;
      height: 44px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ef4444;
      font-weight: bold;
      font-size: 20px;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: #ffffff;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      background: #3b82f6;
      color: #ffffff;
      margin-top: 4px;
    }
    .message {
      font-size: 1rem;
      color: #94a3b8;
      line-height: 1.6;
      margin-bottom: 2rem;
    }
    .meta-box {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1.5rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
    }
    .meta-row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      border-bottom: 1px solid #1e293b;
    }
    .meta-row:last-child {
      border-bottom: none;
    }
    .meta-label {
      color: #64748b;
    }
    .meta-value {
      color: #cbd5e1;
      font-weight: 500;
    }
    .footer {
      text-align: center;
      font-size: 0.75rem;
      color: #475569;
      border-top: 1px solid #1e293b;
      padding-top: 1.25rem;
    }
    .footer a {
      color: #3b82f6;
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="shield-icon">🛡️</div>
      <div>
        <h1>Security Block</h1>
        <span class="badge">NextGuard WAF</span>
      </div>
    </div>
    <p class="message">
      Access to this resource was blocked due to suspicious activity violating security policies (<strong>${escapeHtml(threatTitle)}</strong>).
    </p>
    <div class="meta-box">
      <div class="meta-row">
        <span class="meta-label">Reason:</span>
        <span class="meta-value">${escapeHtml(verdict.reason || 'Security threat detected')}</span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Client IP:</span>
        <span class="meta-value">${escapeHtml(verdict.clientIp)}</span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Request ID:</span>
        <span class="meta-value">${escapeHtml(verdict.requestId)}</span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Timestamp:</span>
        <span class="meta-value">${escapeHtml(dateFormatted)}</span>
      </div>
    </div>
    <div class="footer">
      Protected by <strong>NextGuard Firewall</strong> &bull; If you believe this is a mistake, contact site administration with your Request ID.
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatThreatTitle(threat?: string): string {
  switch (threat) {
    case 'sql_injection':
      return 'SQL Injection Detected';
    case 'xss':
      return 'Cross-Site Scripting (XSS) Detected';
    case 'command_injection':
      return 'Command Injection Detected';
    case 'path_traversal':
      return 'Path Traversal Detected';
    case 'rate_limit_exceeded':
      return 'Rate Limit / DoS Protection Triggered';
    case 'bad_bot':
      return 'Automated Scanner or Malicious Bot Detected';
    case 'ip_blacklisted':
      return 'IP Address Blacklisted';
    case 'payload_too_large':
      return 'Payload Size Limit Exceeded';
    default:
      return 'Suspicious Request Blocked';
  }
}
