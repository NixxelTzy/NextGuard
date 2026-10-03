/**
 * NextGuard - IP Filter & CIDR Matcher
 * Supports IPv4/IPv6 single addresses, wildcards, and CIDR subnet notations.
 */
import { IPFilterConfig } from '../types.js';
export declare class IPFilter {
    private whitelistSubnets;
    private blacklistSubnets;
    private whitelistExact;
    private blacklistExact;
    private trustProxy;
    private customIpHeader?;
    constructor(config?: IPFilterConfig);
    /**
     * Resolves the real client IP from request headers or socket info
     */
    resolveClientIp(headers: Record<string, string | string[] | undefined>, socketIp?: string): string;
    isWhitelisted(ip: string): boolean;
    isBlacklisted(ip: string): boolean;
}
//# sourceMappingURL=ip-filter.d.ts.map