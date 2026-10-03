/**
 * NextGuard - Threat Intelligence, Device Fingerprinting & Forensics
 * Extracts detailed client forensic data (Device, OS, Browser, Geo-coordinates, ISP)
 * from incoming attack requests to assist with defensive monitoring and telemetry.
 */

import { RequestContext, ThreatType, InspectionVerdict } from '../types.js';

export interface GeoLocation {
  country?: string;
  countryCode?: string;
  city?: string;
  region?: string;
  coordinates?: {
    latitude: number;
    longitude: number;
  };
  isp?: string;
  timezone?: string;
}

export interface ClientDeviceFingerprint {
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'bot_scanner' | 'unknown';
  os: string;
  browser: string;
  userAgent: string;
  isAutomatedTool: boolean;
}

export interface ThreatForensicRecord {
  eventId: string;
  timestamp: number;
  clientIp: string;
  geo: GeoLocation;
  client: ClientDeviceFingerprint;
  threat: {
    type: ThreatType;
    reason: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    statusCode: number;
    parameter?: string;
    location?: string;
  };
  request: {
    method: string;
    url: string;
    path: string;
    headers: Record<string, string>;
  };
}

export interface TelemetryConfig {
  enabled?: boolean;
  /** Max records to keep in in-memory ring buffer (default: 500) */
  maxHistory?: number;
  /** Webhook URL for alerting (Slack, Discord, or Custom SIEM API) */
  webhookUrl?: string;
  /** Custom geolocation resolver function (e.g. MaxMind or ip-api integration) */
  geoResolver?: (ip: string, headers: Record<string, string>) => Promise<GeoLocation> | GeoLocation;
}

/**
 * Parses user-agent strings into structured device and OS information
 */
export function parseDeviceFingerprint(ua = ''): ClientDeviceFingerprint {
  const lowerUa = ua.toLowerCase();

  // 1. Detect Automated Tools & Scanners
  const isAutomated =
    lowerUa.includes('sqlmap') ||
    lowerUa.includes('nikto') ||
    lowerUa.includes('nuclei') ||
    lowerUa.includes('nmap') ||
    lowerUa.includes('wfuzz') ||
    lowerUa.includes('curl/') ||
    lowerUa.includes('python-requests') ||
    lowerUa.includes('postman') ||
    lowerUa.includes('gobuster') ||
    lowerUa.includes('dirbuster');

  // 2. Detect Device Type
  let deviceType: ClientDeviceFingerprint['deviceType'] = 'unknown';
  if (isAutomated) {
    deviceType = 'bot_scanner';
  } else if (/ipad|tablet|playbook|silk/i.test(lowerUa)) {
    deviceType = 'tablet';
  } else if (/mobile|iphone|ipod|android.*mobile|blackberry|iemobile|opera mini/i.test(lowerUa)) {
    deviceType = 'mobile';
  } else if (ua.length > 0) {
    deviceType = 'desktop';
  }

  // 3. Detect Operating System
  let os = 'Unknown OS';
  if (/windows nt 10/i.test(ua)) os = 'Windows 10/11';
  else if (/windows nt 6\.3/i.test(ua)) os = 'Windows 8.1';
  else if (/windows nt 6\.1/i.test(ua)) os = 'Windows 7';
  else if (/windows/i.test(ua)) os = 'Windows';
  else if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
  else if (/macintosh|mac os x/i.test(ua)) os = 'macOS';
  else if (/linux/i.test(ua)) os = 'Linux';
  else if (/kali/i.test(ua)) os = 'Kali Linux';
  else if (isAutomated) os = 'Automated CLI / Script';

  // 4. Detect Browser / Tool
  let browser = 'Unknown Client';
  if (/sqlmap/i.test(ua)) browser = 'sqlmap (Exploit Scanner)';
  else if (/nikto/i.test(ua)) browser = 'Nikto (Vulnerability Scanner)';
  else if (/nuclei/i.test(ua)) browser = 'Nuclei (Security Scanner)';
  else if (/curl/i.test(ua)) browser = 'cURL (CLI Tool)';
  else if (/python-requests/i.test(ua)) browser = 'Python Requests';
  else if (/edg\//i.test(ua)) browser = 'Microsoft Edge';
  else if (/chrome\//i.test(ua)) browser = 'Google Chrome';
  else if (/firefox\//i.test(ua)) browser = 'Mozilla Firefox';
  else if (/safari\//i.test(ua) && !/chrome\//i.test(ua)) browser = 'Apple Safari';
  else if (/postman/i.test(ua)) browser = 'Postman Runtime';

  return {
    deviceType,
    os,
    browser,
    userAgent: ua,
    isAutomatedTool: isAutomated,
  };
}

/**
 * Extracts Geolocation data from reverse proxies (Cloudflare, Nginx, AWS CloudFront)
 * or fallback resolver
 */
export function extractGeoFromHeaders(headers: Record<string, string>): GeoLocation {
  const geo: GeoLocation = {};

  // Cloudflare Geolocation Headers (Industry standard)
  if (headers['cf-ipcountry']) {
    geo.countryCode = headers['cf-ipcountry'].toUpperCase();
  }
  if (headers['cf-ipcity']) {
    geo.city = headers['cf-ipcity'];
  }
  if (headers['cf-region']) {
    geo.region = headers['cf-region'];
  }
  if (headers['cf-timezone']) {
    geo.timezone = headers['cf-timezone'];
  }
  if (headers['cf-iplatitude'] && headers['cf-iplongitude']) {
    const lat = parseFloat(headers['cf-iplatitude']);
    const lon = parseFloat(headers['cf-iplongitude']);
    if (!isNaN(lat) && !isNaN(lon)) {
      geo.coordinates = { latitude: lat, longitude: lon };
    }
  }

  // AWS CloudFront Geolocation Headers
  if (!geo.countryCode && headers['cloudfront-viewer-country']) {
    geo.countryCode = headers['cloudfront-viewer-country'].toUpperCase();
  }
  if (!geo.city && headers['cloudfront-viewer-city']) {
    geo.city = headers['cloudfront-viewer-city'];
  }
  if (!geo.coordinates && headers['cloudfront-viewer-latitude'] && headers['cloudfront-viewer-longitude']) {
    const lat = parseFloat(headers['cloudfront-viewer-latitude']);
    const lon = parseFloat(headers['cloudfront-viewer-longitude']);
    if (!isNaN(lat) && !isNaN(lon)) {
      geo.coordinates = { latitude: lat, longitude: lon };
    }
  }

  // Vercel Geolocation Headers
  if (!geo.countryCode && headers['x-vercel-ip-country']) {
    geo.countryCode = headers['x-vercel-ip-country'].toUpperCase();
  }
  if (!geo.city && headers['x-vercel-ip-city']) {
    geo.city = headers['x-vercel-ip-city'];
  }
  if (!geo.coordinates && headers['x-vercel-ip-latitude'] && headers['x-vercel-ip-longitude']) {
    const lat = parseFloat(headers['x-vercel-ip-latitude']);
    const lon = parseFloat(headers['x-vercel-ip-longitude']);
    if (!isNaN(lat) && !isNaN(lon)) {
      geo.coordinates = { latitude: lat, longitude: lon };
    }
  }

  return geo;
}

export class ThreatForensicsCollector {
  private enabled: boolean;
  private maxHistory: number;
  private webhookUrl?: string;
  private geoResolver?: TelemetryConfig['geoResolver'];
  private history: ThreatForensicRecord[] = [];

  constructor(config?: TelemetryConfig | boolean) {
    if (typeof config === 'boolean') {
      this.enabled = config;
      this.maxHistory = 500;
    } else {
      this.enabled = config?.enabled ?? true;
      this.maxHistory = config?.maxHistory ?? 500;
      this.webhookUrl = config?.webhookUrl;
      this.geoResolver = config?.geoResolver;
    }
  }

  /**
   * Captures and analyzes forensic metadata for a blocked or monitored threat event
   */
  public async capture(verdict: InspectionVerdict, req: RequestContext): Promise<ThreatForensicRecord> {
    const normalizedHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers || {})) {
      if (typeof v === 'string') normalizedHeaders[k.toLowerCase()] = v;
      else if (Array.isArray(v)) normalizedHeaders[k.toLowerCase()] = v[0];
    }

    // 1. Device and OS fingerprint
    const ua = normalizedHeaders['user-agent'] || '';
    const client = parseDeviceFingerprint(ua);

    // 2. Geolocation resolution
    let geo = extractGeoFromHeaders(normalizedHeaders);
    if (this.geoResolver && (!geo.countryCode || !geo.coordinates)) {
      try {
        const customGeo = await this.geoResolver(verdict.clientIp, normalizedHeaders);
        geo = { ...geo, ...customGeo };
      } catch (err) {
        console.error('[NextGuard:Forensics] Error in custom geoResolver:', err);
      }
    }

    // 3. Threat severity calculation
    let severity: ThreatForensicRecord['threat']['severity'] = 'medium';
    switch (verdict.threatType) {
      case 'command_injection':
      case 'prototype_pollution':
      case 'honeypot_triggered':
        severity = 'critical';
        break;
      case 'sql_injection':
      case 'nosql_injection':
      case 'path_traversal':
      case 'ssrf':
        severity = 'high';
        break;
      case 'xss':
      case 'bad_bot':
      case 'ip_blacklisted':
        severity = 'medium';
        break;
      default:
        severity = 'low';
    }

    const record: ThreatForensicRecord = {
      eventId: verdict.requestId,
      timestamp: verdict.timestamp,
      clientIp: verdict.clientIp,
      geo,
      client,
      threat: {
        type: verdict.threatType || 'custom_rule_violation',
        reason: verdict.reason || 'Blocked by firewall policy',
        severity,
        statusCode: verdict.statusCode,
        parameter: verdict.parameter,
        location: verdict.location,
      },
      request: {
        method: req.method,
        url: req.url,
        path: req.url.split('?')[0],
        headers: normalizedHeaders,
      },
    };

    if (this.enabled) {
      this.history.unshift(record);
      if (this.history.length > this.maxHistory) {
        this.history.pop();
      }

      // Optional webhook alert notification (fire-and-forget)
      if (this.webhookUrl) {
        this.sendWebhookAlert(record).catch(() => {});
      }
    }

    return record;
  }

  private async sendWebhookAlert(record: ThreatForensicRecord): Promise<void> {
    if (!this.webhookUrl) return;

    try {
      // Formats as JSON payload compatible with Slack, Discord, and custom webhooks
      const isDiscord = this.webhookUrl.includes('discord.com');
      const isSlack = this.webhookUrl.includes('slack.com');

      let payload: unknown;

      if (isDiscord) {
        payload = {
          embeds: [
            {
              title: `🛡️ NextGuard Threat Blocked: ${record.threat.type.toUpperCase()}`,
              color: record.threat.severity === 'critical' ? 0xff0000 : 0xff9900,
              fields: [
                { name: 'Attacker IP', value: `\`${record.clientIp}\``, inline: true },
                { name: 'Device / OS', value: `${record.client.deviceType} (${record.client.os})`, inline: true },
                { name: 'Client Tool', value: record.client.browser, inline: true },
                { name: 'Target Path', value: `\`${record.request.method} ${record.request.path}\``, inline: false },
                { name: 'Reason', value: record.threat.reason, inline: false },
                {
                  name: 'Location',
                  value: record.geo.countryCode
                    ? `${record.geo.city || 'Unknown City'}, ${record.geo.countryCode} (Coords: ${record.geo.coordinates?.latitude ?? 'N/A'}, ${record.geo.coordinates?.longitude ?? 'N/A'})`
                    : 'Location headers not provided',
                  inline: false,
                },
              ],
              timestamp: new Date(record.timestamp).toISOString(),
            },
          ],
        };
      } else if (isSlack) {
        payload = {
          text: `🛡️ *[NextGuard Alert]* Threat \`${record.threat.type}\` blocked from \`${record.clientIp}\` on \`${record.request.path}\`. Device: ${record.client.os} (${record.client.browser}).`,
        };
      } else {
        payload = record;
      }

      await fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      console.error('[NextGuard:Forensics] Failed to send webhook alert:', err);
    }
  }

  public getHistory(limit = 100): ThreatForensicRecord[] {
    return this.history.slice(0, limit);
  }

  public clearHistory(): void {
    this.history = [];
  }
}
