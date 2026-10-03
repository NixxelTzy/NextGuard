/**
 * NextGuard - Defensive HTTP Tarpit
 * Safely delays response to malicious bots and scanners, exhausting their thread pools
 * and mitigating automated vulnerability fuzzing.
 */

import { TarpitConfig, ThreatType } from '../types.js';

export class DefensiveTarpit {
  private enabled: boolean;
  private delayMs: number;
  private applyOnThreats: Set<ThreatType> | null;

  constructor(config?: TarpitConfig | boolean) {
    if (typeof config === 'boolean') {
      this.enabled = config;
      this.delayMs = 3000;
      this.applyOnThreats = null; // all threats
    } else {
      this.enabled = config?.enabled ?? false; // default false so standard responses are fast
      this.delayMs = config?.delayMs ?? 3000;
      this.applyOnThreats = config?.applyOnThreats ? new Set(config.applyOnThreats) : null;
    }
  }

  /**
   * Applies delay if tarpit is enabled for this threat type
   */
  public async delay(threat?: ThreatType): Promise<void> {
    if (!this.enabled) return;

    if (this.applyOnThreats && threat && !this.applyOnThreats.has(threat)) {
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, this.delayMs));
  }

  public isEnabled(): boolean {
    return this.enabled;
  }
}
