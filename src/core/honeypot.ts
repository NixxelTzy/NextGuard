/**
 * NextGuard - Active Deception & Honeypot Trap
 * Lures automated scanners and exploit bots into tripwire endpoints,
 * immediately identifying and jailing them.
 */

import { HoneypotConfig } from '../types.js';

export const DEFAULT_HONEYPOT_PATHS: (string | RegExp)[] = [
  /^\/\.env(?:\..*)?$/i,
  /^\/\.git(?:\/.*)?$/i,
  /^\/\.aws(?:\/.*)?$/i,
  /^\/\.ssh(?:\/.*)?$/i,
  /^\/wp-admin(?:\/.*)?$/i,
  /^\/wp-login\.php$/i,
  /^\/wp-content(?:\/.*)?$/i,
  /^\/xmlrpc\.php$/i,
  /^\/phpmyadmin(?:\/.*)?$/i,
  /^\/pma(?:\/.*)?$/i,
  /^\/myadmin(?:\/.*)?$/i,
  /^\/actuator(?:\/.*)?$/i,
  /^\/solr(?:\/.*)?$/i,
  /^\/autodiscover\/autodiscover\.xml$/i,
  /^\/web\.config$/i,
  /^\/\.ds_store$/i,
  /^\/id_rsa$/i,
  /^\/backup(?:\.sql|\.tar|\.zip|\.gz)?$/i,
  /^\/dump\.sql$/i,
];

export class HoneypotTrap {
  private enabled: boolean;
  private trapPaths: (string | RegExp)[];
  private jailDurationMs: number;

  constructor(config?: HoneypotConfig | boolean) {
    if (typeof config === 'boolean') {
      this.enabled = config;
      this.trapPaths = [...DEFAULT_HONEYPOT_PATHS];
      this.jailDurationMs = 24 * 60 * 60 * 1000; // 24 hours
    } else {
      this.enabled = config?.enabled ?? true;
      this.trapPaths = config?.trapPaths ?? [...DEFAULT_HONEYPOT_PATHS];
      this.jailDurationMs = config?.jailDurationMs ?? 24 * 60 * 60 * 1000;
    }
  }

  public isTrap(pathname: string): boolean {
    if (!this.enabled) return false;

    const normalized = pathname.toLowerCase();

    for (const pattern of this.trapPaths) {
      if (pattern instanceof RegExp) {
        if (pattern.test(normalized)) return true;
      } else if (typeof pattern === 'string') {
        if (pattern.endsWith('*')) {
          const base = pattern.slice(0, -1).toLowerCase();
          if (normalized.startsWith(base)) return true;
        } else if (pattern.toLowerCase() === normalized) {
          return true;
        }
      }
    }

    return false;
  }

  public getJailDuration(): number {
    return this.jailDurationMs;
  }
}
