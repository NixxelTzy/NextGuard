/**
 * NextGuard - Adaptive IP Reputation & Strike Engine
 * Tracks threat strikes per IP and escalates jail penalties (Fail2Ban-style).
 */
import { ReputationConfig, ThreatType } from '../types.js';
interface StrikeRecord {
    strikes: number;
    lastStrikeTime: number;
    jailCount: number;
}
export declare class ReputationEngine {
    private enabled;
    private maxStrikes;
    private windowMs;
    private baseJailMs;
    private records;
    constructor(config?: ReputationConfig | boolean);
    /**
     * Adds strikes for a detected threat.
     * Returns whether the IP should now be jailed and for how many milliseconds.
     */
    addStrike(ip: string, threat?: ThreatType): {
        shouldJail: boolean;
        jailDurationMs: number;
        totalStrikes: number;
    };
    getRecord(ip: string): StrikeRecord | undefined;
    clear(): void;
}
export {};
//# sourceMappingURL=reputation.d.ts.map