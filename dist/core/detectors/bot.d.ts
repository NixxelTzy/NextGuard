/**
 * NextGuard - Bad Bot & Vulnerability Scanner Detector
 * Identifies automated scanners, exploit kits, scrapers, and malicious crawlers.
 */
import { BotConfig } from '../../types.js';
export declare class BotDetector {
    private blockEmpty;
    private knownScanners;
    private customBlacklist;
    private whitelist;
    constructor(config?: BotConfig);
    detectUserAgent(userAgent: string | undefined): {
        detected: boolean;
        reason?: string;
    };
}
//# sourceMappingURL=bot.d.ts.map