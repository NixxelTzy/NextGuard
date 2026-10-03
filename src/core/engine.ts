/**
 * NextGuard - Core Security Engine
 * Orchestrates all detection modules, rate limiting, and rule enforcement.
 */

import {
  NextGuardConfig,
  RequestContext,
  InspectionVerdict,
  EndpointRuleOverride,
  RateLimitConfig,
  SQLiConfig,
  XSSConfig,
  CommandInjectionConfig,
  PathTraversalConfig,
  BotConfig,
} from '../types.js';
import { SQLInjectionDetector } from './detectors/sqli.js';
import { NoSQLInjectionDetector } from './detectors/nosqli.js';
import { PrototypePollutionDetector } from './detectors/prototype-pollution.js';
import { SSRFDetector } from './detectors/ssrf.js';
import { XSSDetector } from './detectors/xss.js';
import { CommandInjectionDetector } from './detectors/command-injection.js';
import { PathTraversalDetector } from './detectors/path-traversal.js';
import { BotDetector } from './detectors/bot.js';
import { RateLimiter } from './rate-limiter.js';
import { IPFilter } from './ip-filter.js';
import { HoneypotTrap } from './honeypot.js';
import { ReputationEngine } from './reputation.js';
import { DefensiveTarpit } from './tarpit.js';
import { ThreatForensicsCollector } from './telemetry.js';

function generateRequestId(): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return `ng_${ts}_${rand}`;
}

function matchPath(pattern: string | RegExp, path: string): boolean {
  if (pattern instanceof RegExp) {
    return pattern.test(path);
  }
  if (pattern.endsWith('*')) {
    const base = pattern.slice(0, -1);
    return path.startsWith(base);
  }
  return pattern === path;
}

export class NextGuardEngine {
  private config: NextGuardConfig;
  private sqliDetector: SQLInjectionDetector;
  private nosqliDetector: NoSQLInjectionDetector;
  private protoDetector: PrototypePollutionDetector;
  private ssrfDetector: SSRFDetector;
  private xssDetector: XSSDetector;
  private cmdDetector: CommandInjectionDetector;
  private pathDetector: PathTraversalDetector;
  private botDetector: BotDetector;
  private rateLimiter: RateLimiter;
  private ipFilter: IPFilter;
  private honeypot: HoneypotTrap;
  private reputation: ReputationEngine;
  private tarpit: DefensiveTarpit;
  private forensics: ThreatForensicsCollector;

  constructor(config: NextGuardConfig = {}) {
    this.config = config;

    const sqliCfg = typeof config.sqlInjection === 'object' ? config.sqlInjection : {};
    this.sqliDetector = new SQLInjectionDetector(sqliCfg);

    const nosqliCfg = typeof config.nosqlInjection === 'object' ? config.nosqlInjection : {};
    this.nosqliDetector = new NoSQLInjectionDetector(nosqliCfg);

    const protoCfg = typeof config.prototypePollution === 'object' ? config.prototypePollution : {};
    this.protoDetector = new PrototypePollutionDetector(protoCfg);

    const ssrfCfg = typeof config.ssrf === 'object' ? config.ssrf : {};
    this.ssrfDetector = new SSRFDetector(ssrfCfg);

    const xssCfg = typeof config.xss === 'object' ? config.xss : {};
    this.xssDetector = new XSSDetector(xssCfg);

    const cmdCfg = typeof config.commandInjection === 'object' ? config.commandInjection : {};
    this.cmdDetector = new CommandInjectionDetector(cmdCfg);

    const pathCfg = typeof config.pathTraversal === 'object' ? config.pathTraversal : {};
    this.pathDetector = new PathTraversalDetector(pathCfg);

    const botCfg = typeof config.badBots === 'object' ? config.badBots : {};
    this.botDetector = new BotDetector(botCfg);

    const rlCfg = typeof config.rateLimit === 'object' ? config.rateLimit : undefined;
    this.rateLimiter = new RateLimiter(rlCfg);

    this.ipFilter = new IPFilter(config.ipFilter);
    this.honeypot = new HoneypotTrap(config.honeypot);
    this.reputation = new ReputationEngine(config.reputation);
    this.tarpit = new DefensiveTarpit(config.tarpit);
    this.forensics = new ThreatForensicsCollector(config.telemetry);
  }

  /**
   * Find matching endpoint override if defined in config.endpoints
   */
  private getEndpointOverride(urlPath: string): EndpointRuleOverride | null {
    if (!this.config.endpoints) return null;

    for (const [pattern, override] of Object.entries(this.config.endpoints)) {
      if (matchPath(pattern, urlPath)) {
        return override;
      }
    }
    return null;
  }

  /**
   * Main inspection method that verifies every incoming request against all firewall rules
   */
  public async inspect(req: RequestContext): Promise<InspectionVerdict> {
    const requestId = generateRequestId();
    const timestamp = Date.now();
    const mode = this.config.mode || 'enforce';
    const clientIp = this.ipFilter.resolveClientIp(req.headers, req.ip);

    // Normalize URL path
    const urlObj = req.url.startsWith('http') ? new URL(req.url) : new URL(`http://localhost${req.url}`);
    const pathname = urlObj.pathname;

    // Auto-populate query from URL if not already provided
    if (!req.query || Object.keys(req.query).length === 0) {
      const q: Record<string, string> = {};
      urlObj.searchParams.forEach((val, k) => {
        q[k] = val;
      });
      if (Object.keys(q).length > 0) {
        req.query = q;
      }
    }

    // 1. Check excluded paths (e.g. Next.js static assets)
    if (this.config.excludePaths) {
      for (const pattern of this.config.excludePaths) {
        if (matchPath(pattern, pathname)) {
          return {
            allowed: true,
            statusCode: 200,
            clientIp,
            requestId,
            timestamp,
            mode,
          };
        }
      }
    }

    // 2. IP Filter: Whitelist
    if (this.ipFilter.isWhitelisted(clientIp)) {
      return {
        allowed: true,
        statusCode: 200,
        clientIp,
        requestId,
        timestamp,
        mode,
      };
    }

    // 3. IP Filter: Blacklist
    if (this.ipFilter.isBlacklisted(clientIp)) {
      const verdict: InspectionVerdict = {
        allowed: mode === 'monitor',
        threatType: 'ip_blacklisted',
        reason: `IP address ${clientIp} is explicitly blacklisted`,
        statusCode: 403,
        clientIp,
        requestId,
        location: 'ip',
        timestamp,
        mode,
      };
      await this.handleVerdict(verdict, req);
      return verdict;
    }

    const override = this.getEndpointOverride(pathname);

    // 3.5. Honeypot Trap (Active Deception)
    const honeypotConfig = override?.honeypot !== undefined ? override.honeypot : this.config.honeypot;
    if (honeypotConfig !== false && this.honeypot.isTrap(pathname)) {
      const jailDuration = this.honeypot.getJailDuration();
      await this.rateLimiter.jailKey(clientIp, jailDuration);

      const verdict: InspectionVerdict = {
        allowed: mode === 'monitor',
        threatType: 'honeypot_triggered',
        reason: `Honeypot trap triggered: ${pathname}. Scanner IP automatically jailed.`,
        statusCode: 403,
        clientIp,
        requestId,
        location: 'url',
        timestamp,
        mode,
      };
      await this.handleVerdict(verdict, req);
      return verdict;
    }

    // 4. Bad Bot / Vulnerability Scanner check
    const botConfig = override?.badBots !== undefined ? override.badBots : this.config.badBots;
    if (botConfig !== false) {
      const userAgentHeader = req.headers['user-agent'];
      const userAgent = Array.isArray(userAgentHeader) ? userAgentHeader[0] : userAgentHeader;
      const botResult = this.botDetector.detectUserAgent(userAgent);
      if (botResult.detected) {
        const verdict: InspectionVerdict = {
          allowed: mode === 'monitor',
          threatType: 'bad_bot',
          reason: botResult.reason || 'Malicious bot or scanner detected',
          statusCode: 403,
          clientIp,
          requestId,
          location: 'header',
          parameter: 'user-agent',
          timestamp,
          mode,
        };
        await this.handleVerdict(verdict, req);
        return verdict;
      }
    }

    // 5. Rate Limiting & DoS Protection
    const rateLimitConfig = override?.rateLimit !== undefined ? override.rateLimit : this.config.rateLimit;
    if (rateLimitConfig !== false) {
      const rlResult = await this.rateLimiter.check(
        { ...req, ip: clientIp },
        typeof rateLimitConfig === 'object' ? rateLimitConfig : undefined
      );

      if (!rlResult.allowed) {
        const verdict: InspectionVerdict = {
          allowed: mode === 'monitor',
          threatType: 'rate_limit_exceeded',
          reason: rlResult.isJailed
            ? `Too many suspicious requests. IP temporarily jailed for ${rlResult.retryAfterSec} seconds.`
            : `Rate limit of ${rlResult.limit} requests exceeded. Try again in ${rlResult.retryAfterSec} seconds.`,
          statusCode: 429,
          clientIp,
          requestId,
          timestamp,
          mode,
        };
        await this.handleVerdict(verdict, req);
        return verdict;
      }
    }

    // 6. Payload size guard
    const payloadCfg = override?.payloadGuard !== undefined ? override.payloadGuard : this.config.payloadGuard;
    if (payloadCfg !== false) {
      const maxSize = typeof payloadCfg === 'object' && payloadCfg.maxBodySize ? payloadCfg.maxBodySize : 10 * 1024 * 1024; // 10MB default
      const contentLength = req.headers['content-length'];
      if (contentLength) {
        const len = parseInt(Array.isArray(contentLength) ? contentLength[0] : contentLength, 10);
        if (!isNaN(len) && len > maxSize) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'payload_too_large',
            reason: `Payload size (${len} bytes) exceeds limit of ${maxSize} bytes`,
            statusCode: 413,
            clientIp,
            requestId,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 7. Path Traversal Check (Inspect URL Path, Query, and Body)
    const pathConfig = override?.pathTraversal !== undefined ? override.pathTraversal : this.config.pathTraversal;
    if (pathConfig !== false) {
      // Check pathname
      const pathResult = this.pathDetector.detectValue(pathname, 'url_path');
      if (pathResult.detected) {
        const verdict: InspectionVerdict = {
          allowed: mode === 'monitor',
          threatType: 'path_traversal',
          reason: 'Path traversal attempt detected in URL',
          matchedPattern: pathResult.pattern,
          statusCode: 403,
          clientIp,
          requestId,
          location: 'url',
          timestamp,
          mode,
        };
        await this.handleVerdict(verdict, req);
        return verdict;
      }

      // Check query
      if (req.query) {
        const qResult = this.pathDetector.detectObject(req.query, 'query');
        if (qResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'path_traversal',
            reason: `Path traversal attempt detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'query',
            parameter: qResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 8. SQL Injection Check
    const sqliConfig = override?.sqlInjection !== undefined ? override.sqlInjection : this.config.sqlInjection;
    if (sqliConfig !== false) {
      // Check query parameters
      if (req.query) {
        const qResult = this.sqliDetector.detectObject(req.query, 'query');
        if (qResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'sql_injection',
            reason: `SQL Injection detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'query',
            parameter: qResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }

      // Check body
      if (req.body) {
        const bResult = this.sqliDetector.detectObject(req.body, 'body');
        if (bResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'sql_injection',
            reason: `SQL Injection detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'body',
            parameter: bResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }

      // Check raw body string if present
      if (req.rawBody && typeof req.rawBody === 'string') {
        const rbResult = this.sqliDetector.detectValue(req.rawBody, 'rawBody');
        if (rbResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'sql_injection',
            reason: 'SQL Injection detected in request payload',
            matchedPattern: rbResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'body',
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 8.5. NoSQL Injection Check
    const nosqliConfig = override?.nosqlInjection !== undefined ? override.nosqlInjection : this.config.nosqlInjection;
    if (nosqliConfig !== false) {
      if (req.query) {
        const qResult = this.nosqliDetector.detectObject(req.query, 'query');
        if (qResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'nosql_injection',
            reason: `NoSQL Injection detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'query',
            parameter: qResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }

      if (req.body) {
        const bResult = this.nosqliDetector.detectObject(req.body, 'body');
        if (bResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'nosql_injection',
            reason: `NoSQL Injection detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'body',
            parameter: bResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 8.6. Prototype Pollution Check
    const protoConfig = override?.prototypePollution !== undefined ? override.prototypePollution : this.config.prototypePollution;
    if (protoConfig !== false) {
      if (req.query) {
        const qResult = this.protoDetector.detectObject(req.query, 'query');
        if (qResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'prototype_pollution',
            reason: `Prototype pollution attempt detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'query',
            parameter: qResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }

      if (req.body) {
        const bResult = this.protoDetector.detectObject(req.body, 'body');
        if (bResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'prototype_pollution',
            reason: `Prototype pollution attempt detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'body',
            parameter: bResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 8.7. SSRF Check
    const ssrfConfig = override?.ssrf !== undefined ? override.ssrf : this.config.ssrf;
    if (ssrfConfig !== false && ssrfConfig !== undefined) {
      if (req.query) {
        const qResult = this.ssrfDetector.detectObject(req.query, 'query');
        if (qResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'ssrf',
            reason: `SSRF target address detected in query parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'query',
            parameter: qResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 9. Cross-Site Scripting (XSS) Check
    const xssConfig = override?.xss !== undefined ? override.xss : this.config.xss;
    if (xssConfig !== false) {
      if (req.query) {
        const qResult = this.xssDetector.detectObject(req.query, 'query');
        if (qResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'xss',
            reason: `XSS attack payload detected in query parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'query',
            parameter: qResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }

      if (req.body) {
        const bResult = this.xssDetector.detectObject(req.body, 'body');
        if (bResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'xss',
            reason: `XSS attack payload detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'body',
            parameter: bResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 10. Command Injection Check
    const cmdConfig = override?.commandInjection !== undefined ? override.commandInjection : this.config.commandInjection;
    if (cmdConfig !== false) {
      if (req.query) {
        const qResult = this.cmdDetector.detectObject(req.query, 'query');
        if (qResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'command_injection',
            reason: `OS Command Injection signature detected in query: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'query',
            parameter: qResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }

      if (req.body) {
        const bResult = this.cmdDetector.detectObject(req.body, 'body');
        if (bResult.detected) {
          const verdict: InspectionVerdict = {
            allowed: mode === 'monitor',
            threatType: 'command_injection',
            reason: `OS Command Injection signature detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: 'body',
            parameter: bResult.parameter,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // 11. Custom Rules evaluation
    if (this.config.customRules && this.config.customRules.length > 0) {
      for (const rule of this.config.customRules) {
        const triggered = await rule.evaluate(req);
        if (triggered) {
          const action = rule.action || 'block';
          const verdict: InspectionVerdict = {
            allowed: action === 'monitor' || mode === 'monitor',
            threatType: 'custom_rule_violation',
            reason: rule.reason || `Custom rule violated: ${rule.name}`,
            statusCode: rule.statusCode || 403,
            clientIp,
            requestId,
            timestamp,
            mode,
          };
          await this.handleVerdict(verdict, req);
          return verdict;
        }
      }
    }

    // Request is clean!
    const verdict: InspectionVerdict = {
      allowed: true,
      statusCode: 200,
      clientIp,
      requestId,
      timestamp,
      mode,
    };
    if (this.config.onAllowed) {
      try {
        await this.config.onAllowed(verdict, req);
      } catch (err) {
        console.error('[NextGuard] Error in onAllowed hook:', err);
      }
    }

    return verdict;
  }

  private async handleVerdict(verdict: InspectionVerdict, req: RequestContext): Promise<void> {
    if (!verdict.allowed || verdict.mode === 'monitor') {
      // 1. Adaptive IP Reputation & Auto-Jail Strike System
      if (verdict.clientIp && verdict.threatType) {
        const { shouldJail, jailDurationMs } = this.reputation.addStrike(verdict.clientIp, verdict.threatType);
        if (shouldJail) {
          await this.rateLimiter.jailKey(verdict.clientIp, jailDurationMs);
        }
      }

      // 2. Defensive HTTP Tarpit (delay attacker response)
      await this.tarpit.delay(verdict.threatType);

      // 3. Threat Forensics & Device/Location Capture
      await this.forensics.capture(verdict, req);

      // 4. User onBlocked callback
      if (this.config.onBlocked) {
        try {
          await this.config.onBlocked(verdict, req);
        } catch (err) {
          console.error('[NextGuard] Error in onBlocked hook:', err);
        }
      }
    }
  }

  public getRateLimiter(): RateLimiter {
    return this.rateLimiter;
  }

  public getIPFilter(): IPFilter {
    return this.ipFilter;
  }

  public getReputation(): ReputationEngine {
    return this.reputation;
  }

  public getHoneypot(): HoneypotTrap {
    return this.honeypot;
  }

  public getTarpit(): DefensiveTarpit {
    return this.tarpit;
  }

  public getForensics(): ThreatForensicsCollector {
    return this.forensics;
  }
}
