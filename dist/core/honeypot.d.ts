/**
 * NextGuard - Active Deception & Honeypot Trap
 * Lures automated scanners and exploit bots into tripwire endpoints,
 * immediately identifying and jailing them.
 */
import { HoneypotConfig } from '../types.js';
export declare const DEFAULT_HONEYPOT_PATHS: (string | RegExp)[];
export declare class HoneypotTrap {
    private enabled;
    private trapPaths;
    private jailDurationMs;
    constructor(config?: HoneypotConfig | boolean);
    isTrap(pathname: string): boolean;
    getJailDuration(): number;
}
//# sourceMappingURL=honeypot.d.ts.map