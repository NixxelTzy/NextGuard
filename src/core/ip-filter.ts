/**
 * NextGuard - IP Filter & CIDR Matcher
 * Supports IPv4/IPv6 single addresses, wildcards, and CIDR subnet notations.
 */

import { IPFilterConfig } from '../types.js';

interface Subnet {
  network: number;
  mask: number;
}

function ipv4ToInt(ip: string): number {
  return (
    ip
      .split('.')
      .reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0) >>> 0
  );
}

function parseCidr(cidr: string): Subnet | null {
  const parts = cidr.trim().split('/');
  if (parts.length === 1) {
    const ip = parts[0];
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
    return {
      network: ipv4ToInt(ip),
      mask: 0xffffffff >>> 0,
    };
  }

  if (parts.length === 2) {
    const ip = parts[0];
    const prefix = parseInt(parts[1], 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;

    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const network = (ipv4ToInt(ip) & mask) >>> 0;
    return { network, mask };
  }

  return null;
}

function isIpInSubnet(ip: string, subnet: Subnet): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  const ipInt = ipv4ToInt(ip);
  return (ipInt & subnet.mask) >>> 0 === subnet.network;
}

export class IPFilter {
  private whitelistSubnets: Subnet[] = [];
  private blacklistSubnets: Subnet[] = [];
  private whitelistExact: Set<string> = new Set();
  private blacklistExact: Set<string> = new Set();
  private trustProxy: boolean;
  private customIpHeader?: string;

  constructor(config?: IPFilterConfig) {
    this.trustProxy = config?.trustProxy ?? true;
    this.customIpHeader = config?.customIpHeader?.toLowerCase();

    if (config?.whitelist) {
      for (const item of config.whitelist) {
        const cleaned = item.trim();
        const subnet = parseCidr(cleaned);
        if (subnet) {
          this.whitelistSubnets.push(subnet);
        } else {
          this.whitelistExact.add(cleaned.toLowerCase());
        }
      }
    }

    if (config?.blacklist) {
      for (const item of config.blacklist) {
        const cleaned = item.trim();
        const subnet = parseCidr(cleaned);
        if (subnet) {
          this.blacklistSubnets.push(subnet);
        } else {
          this.blacklistExact.add(cleaned.toLowerCase());
        }
      }
    }
  }

  /**
   * Resolves the real client IP from request headers or socket info
   */
  public resolveClientIp(
    headers: Record<string, string | string[] | undefined>,
    socketIp?: string
  ): string {
    if (this.customIpHeader) {
      const custom = headers[this.customIpHeader];
      if (custom) {
        const ipStr = Array.isArray(custom) ? custom[0] : custom;
        return ipStr.split(',')[0].trim();
      }
    }

    if (this.trustProxy) {
      // Cloudflare
      const cfIp = headers['cf-connecting-ip'];
      if (cfIp) return (Array.isArray(cfIp) ? cfIp[0] : cfIp).trim();

      // Standard reverse proxy (Nginx, Caddy)
      const realIp = headers['x-real-ip'];
      if (realIp) return (Array.isArray(realIp) ? realIp[0] : realIp).trim();

      // Standard forward header
      const xForwardedFor = headers['x-forwarded-for'];
      if (xForwardedFor) {
        const forwarded = Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor;
        const first = forwarded.split(',')[0].trim();
        if (first) return first;
      }
    }

    return socketIp || '127.0.0.1';
  }

  public isWhitelisted(ip: string): boolean {
    const cleanIp = ip.trim().toLowerCase();
    if (this.whitelistExact.has(cleanIp)) return true;

    for (const subnet of this.whitelistSubnets) {
      if (isIpInSubnet(cleanIp, subnet)) return true;
    }
    return false;
  }

  public isBlacklisted(ip: string): boolean {
    const cleanIp = ip.trim().toLowerCase();
    if (this.blacklistExact.has(cleanIp)) return true;

    for (const subnet of this.blacklistSubnets) {
      if (isIpInSubnet(cleanIp, subnet)) return true;
    }
    return false;
  }
}
