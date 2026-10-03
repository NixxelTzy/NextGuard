import { describe, it, expect } from 'vitest';
import {
  parseDeviceFingerprint,
  extractGeoFromHeaders,
  ThreatForensicsCollector,
} from '../src/core/telemetry.js';
import { NextGuardEngine } from '../src/core/engine.js';
import { NextGuard as NextGuardNode } from '../packages/node/src/index.js';
import { NextGuard as NextGuardNext } from '../packages/next/src/index.js';

describe('Threat Forensics & Device Fingerprinting', () => {
  describe('parseDeviceFingerprint', () => {
    it('identifies automated exploit scanners and security tools', () => {
      const sqlmap = parseDeviceFingerprint('sqlmap/1.5.2#stable (http://sqlmap.org)');
      expect(sqlmap.isAutomatedTool).toBe(true);
      expect(sqlmap.deviceType).toBe('bot_scanner');
      expect(sqlmap.browser).toContain('sqlmap');

      const nikto = parseDeviceFingerprint('Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)');
      expect(nikto.isAutomatedTool).toBe(true);
      expect(nikto.deviceType).toBe('bot_scanner');

      const curl = parseDeviceFingerprint('curl/7.88.1');
      expect(curl.isAutomatedTool).toBe(true);
    });

    it('identifies desktop Windows and Mac browsers', () => {
      const winChrome = parseDeviceFingerprint(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      );
      expect(winChrome.deviceType).toBe('desktop');
      expect(winChrome.os).toBe('Windows 10/11');
      expect(winChrome.browser).toBe('Google Chrome');
      expect(winChrome.isAutomatedTool).toBe(false);

      const macSafari = parseDeviceFingerprint(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
      );
      expect(macSafari.deviceType).toBe('desktop');
      expect(macSafari.os).toBe('macOS');
      expect(macSafari.browser).toBe('Apple Safari');
    });

    it('identifies mobile devices (Android, iPhone)', () => {
      const iphone = parseDeviceFingerprint(
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
      );
      expect(iphone.deviceType).toBe('mobile');
      expect(iphone.os).toBe('iOS');

      const android = parseDeviceFingerprint(
        'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36'
      );
      expect(android.deviceType).toBe('mobile');
      expect(android.os).toBe('Android');
    });
  });

  describe('extractGeoFromHeaders', () => {
    it('extracts country, city, and coordinates from Cloudflare headers', () => {
      const headers = {
        'cf-ipcountry': 'ID',
        'cf-ipcity': 'Jakarta',
        'cf-region': 'Jakarta',
        'cf-timezone': 'Asia/Jakarta',
        'cf-iplatitude': '-6.2088',
        'cf-iplongitude': '106.8456',
      };

      const geo = extractGeoFromHeaders(headers);
      expect(geo.countryCode).toBe('ID');
      expect(geo.city).toBe('Jakarta');
      expect(geo.region).toBe('Jakarta');
      expect(geo.timezone).toBe('Asia/Jakarta');
      expect(geo.coordinates).toEqual({
        latitude: -6.2088,
        longitude: 106.8456,
      });
    });

    it('extracts country and coordinates from CloudFront headers', () => {
      const headers = {
        'cloudfront-viewer-country': 'US',
        'cloudfront-viewer-city': 'Ashburn',
        'cloudfront-viewer-latitude': '39.0437',
        'cloudfront-viewer-longitude': '-77.4875',
      };

      const geo = extractGeoFromHeaders(headers);
      expect(geo.countryCode).toBe('US');
      expect(geo.city).toBe('Ashburn');
      expect(geo.coordinates?.latitude).toBe(39.0437);
      expect(geo.coordinates?.longitude).toBe(-77.4875);
    });
  });

  describe('ThreatForensicsCollector & Engine Integration', () => {
    it('captures threat forensic record with device & geo on attack', async () => {
      const engine = new NextGuardEngine({
        sqlInjection: { enabled: true },
        badBots: false,
        telemetry: { enabled: true },
      });

      const attackReq = {
        url: '/api/search?q=1%27%20OR%201=1--',
        method: 'GET',
        ip: '198.51.100.42',
        headers: {
          'user-agent': 'sqlmap/1.5.2#stable',
          'cf-ipcountry': 'SG',
          'cf-ipcity': 'Singapore',
          'cf-iplatitude': '1.3521',
          'cf-iplongitude': '103.8198',
        },
      };

      const verdict = await engine.inspect(attackReq);
      expect(verdict.allowed).toBe(false);

      const logs = engine.getForensics().getHistory();
      expect(logs.length).toBeGreaterThanOrEqual(1);

      const log = logs[0];
      expect(log.clientIp).toBe('198.51.100.42');
      expect(log.threat.type).toBe('sql_injection');
      expect(log.threat.severity).toBe('high');
      expect(log.client.isAutomatedTool).toBe(true);
      expect(log.client.browser).toContain('sqlmap');
      expect(log.geo.countryCode).toBe('SG');
      expect(log.geo.city).toBe('Singapore');
      expect(log.geo.coordinates).toEqual({ latitude: 1.3521, longitude: 103.8198 });
    });

    it('@nextguard/node guard.getThreatLogs() exposes captured forensics', async () => {
      const guard = NextGuardNode({
        logging: false,
        sqlInjection: { enabled: true },
      });

      const mw = guard.middleware();
      const mockReq: any = {
        method: 'GET',
        url: "/api/test?x=1' OR 1=1--",
        originalUrl: "/api/test?x=1' OR 1=1--",
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
          'cf-ipcountry': 'DE',
          'cf-ipcity': 'Frankfurt',
        },
        query: { x: "1' OR 1=1--" },
        socket: { remoteAddress: '192.0.2.1' },
      };

      const mockRes: any = {
        status() { return this; },
        setHeader() { return this; },
        json() {},
        send() {},
      };

      await mw(mockReq, mockRes, () => {});

      const threatLogs = guard.getThreatLogs();
      expect(threatLogs.length).toBe(1);
      expect(threatLogs[0].client.os).toBe('Windows 10/11');
      expect(threatLogs[0].geo.countryCode).toBe('DE');
      expect(threatLogs[0].geo.city).toBe('Frankfurt');
    });

    it('@nextguard/next guard.getThreatLogs() exposes captured forensics in Next.js', async () => {
      const guard = NextGuardNext({
        logging: false,
        sqlInjection: { enabled: true },
      });

      const handler = guard.middleware();
      const req = new Request('https://example.com/api/test?q=1%27%20OR%201=1--', {
        method: 'GET',
        headers: {
          'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
          'cf-ipcountry': 'JP',
          'cf-ipcity': 'Tokyo',
        },
      });

      await handler(req);

      const threatLogs = guard.getThreatLogs();
      expect(threatLogs.length).toBe(1);
      expect(threatLogs[0].client.deviceType).toBe('mobile');
      expect(threatLogs[0].client.os).toBe('iOS');
      expect(threatLogs[0].geo.countryCode).toBe('JP');
      expect(threatLogs[0].geo.city).toBe('Tokyo');
    });
  });
});
