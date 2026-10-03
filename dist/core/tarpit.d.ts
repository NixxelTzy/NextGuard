/**
 * NextGuard - Defensive HTTP Tarpit
 * Safely delays response to malicious bots and scanners, exhausting their thread pools
 * and mitigating automated vulnerability fuzzing.
 */
import { TarpitConfig, ThreatType } from '../types.js';
export declare class DefensiveTarpit {
    private enabled;
    private delayMs;
    private applyOnThreats;
    constructor(config?: TarpitConfig | boolean);
    /**
     * Applies delay if tarpit is enabled for this threat type
     */
    delay(threat?: ThreatType): Promise<void>;
    isEnabled(): boolean;
}
//# sourceMappingURL=tarpit.d.ts.map