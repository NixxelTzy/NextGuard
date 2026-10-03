/**
 * NextGuard - Bad Bot & Vulnerability Scanner Detector
 * Identifies automated scanners, exploit kits, scrapers, and malicious crawlers.
 */

import { BotConfig } from '../../types.js';

const KNOWN_SCANNERS: RegExp[] = [
  /sqlmap/i,
  /nikto/i,
  /acunetix/i,
  /dirbuster/i,
  /gobuster/i,
  /ffuf/i,
  /wpscan/i,
  /nmap/i,
  /masscan/i,
  /zgrab/i,
  /censys/i,
  /shodan/i,
  /nessus/i,
  /openvas/i,
  /nuclei/i,
  /hydra/i,
  /metasploit/i,
  /burpcollaborator/i,
  /arachni/i,
  /havij/i,
  /pangolin/i,
  /qualys/i,
  /netsparker/i,
  /appscan/i,
  /wfuzz/i,
  /zaproxy/i,
];

const DEFAULT_WHITELIST: RegExp[] = [
  /googlebot/i,
  /bingbot/i,
  /slurp/i,
  /duckduckbot/i,
  /baiduspider/i,
  /yandexbot/i,
  /facebot/i,
  /ia_archiver/i,
  /twitterbot/i,
  /linkedinbot/i,
  /slackbot/i,
  /discordbot/i,
  /telegrambot/i,
  /applebot/i,
];

export class BotDetector {
  private blockEmpty: boolean;
  private knownScanners: boolean;
  private customBlacklist: (string | RegExp)[];
  private whitelist: (string | RegExp)[];

  constructor(config?: BotConfig) {
    this.blockEmpty = config?.blockEmptyUserAgent ?? false;
    this.knownScanners = config?.knownScanners ?? true;
    this.customBlacklist = config?.customBlacklist ?? [];
    this.whitelist = config?.whitelist ?? DEFAULT_WHITELIST;
  }

  public detectUserAgent(userAgent: string | undefined): { detected: boolean; reason?: string } {
    if (!userAgent || userAgent.trim() === '') {
      if (this.blockEmpty) {
        return { detected: true, reason: 'Empty User-Agent header is blocked' };
      }
      return { detected: false };
    }

    const ua = userAgent.trim();

    // Check whitelist first
    for (const allowed of this.whitelist) {
      if (typeof allowed === 'string') {
        if (ua.toLowerCase().includes(allowed.toLowerCase())) return { detected: false };
      } else if (allowed instanceof RegExp) {
        if (allowed.test(ua)) return { detected: false };
      }
    }

    // Check custom blacklist
    for (const blocked of this.customBlacklist) {
      if (typeof blocked === 'string') {
        if (ua.toLowerCase().includes(blocked.toLowerCase())) {
          return { detected: true, reason: `User-Agent matches blocked string: ${blocked}` };
        }
      } else if (blocked instanceof RegExp) {
        if (blocked.test(ua)) {
          return { detected: true, reason: `User-Agent matches blocked pattern: ${blocked}` };
        }
      }
    }

    // Check known vulnerability scanners
    if (this.knownScanners) {
      for (const scanner of KNOWN_SCANNERS) {
        if (scanner.test(ua)) {
          return { detected: true, reason: `Known vulnerability scanner detected: ${scanner.source}` };
        }
      }
    }

    return { detected: false };
  }
}
