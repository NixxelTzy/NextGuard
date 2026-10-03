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

const THREAT_STRIKE_WEIGHTS: Record<ThreatType, number> = {
  honeypot_triggered: 5,
  command_injection: 5,
  prototype_pollution: 5,
  sql_injection: 3,
  nosql_injection: 3,
  ssrf: 3,
  path_traversal: 3,
  xss: 3,
  bad_bot: 2,
  rate_limit_exceeded: 1,
  payload_too_large: 1,
  suspicious_header: 1,
  custom_rule_violation: 2,
  ip_blacklisted: 5,
};

export class ReputationEngine {
  private enabled: boolean;
  private maxStrikes: number;
  private windowMs: number;
  private baseJailMs: number;
  private records: Map<string, StrikeRecord> = new Map();

  constructor(config?: ReputationConfig | boolean) {
    if (typeof config === 'boolean') {
      this.enabled = config;
      this.maxStrikes = 5;
      this.windowMs = 60 * 60 * 1000; // 1 hour
      this.baseJailMs = 15 * 60 * 1000; // 15 mins
    } else {
      this.enabled = config?.enabled ?? false;
      this.maxStrikes = config?.maxStrikes ?? 5;
      this.windowMs = config?.windowMs ?? 60 * 60 * 1000;
      this.baseJailMs = config?.jailDurationMs ?? 15 * 60 * 1000;
    }
  }

  /**
   * Adds strikes for a detected threat.
   * Returns whether the IP should now be jailed and for how many milliseconds.
   */
  public addStrike(ip: string, threat?: ThreatType): { shouldJail: boolean; jailDurationMs: number; totalStrikes: number } {
    if (!this.enabled || ip === '127.0.0.1' || ip === '::1') {
      return { shouldJail: false, jailDurationMs: 0, totalStrikes: 0 };
    }

    const now = Date.now();
    let record = this.records.get(ip);

    if (!record || (now - record.lastStrikeTime) > this.windowMs) {
      record = { strikes: 0, lastStrikeTime: now, jailCount: record ? record.jailCount : 0 };
      this.records.set(ip, record);
    }

    const weight = threat ? (THREAT_STRIKE_WEIGHTS[threat] ?? 1) : 1;
    record.strikes += weight;
    record.lastStrikeTime = now;

    if (record.strikes >= this.maxStrikes) {
      record.jailCount++;
      record.strikes = 0; // reset strikes after jailing

      // Escalating penalty: 15m -> 2h -> 24h -> 7d
      let multiplier = 1;
      if (record.jailCount === 2) multiplier = 8; // 2 hours
      else if (record.jailCount === 3) multiplier = 96; // 24 hours
      else if (record.jailCount >= 4) multiplier = 672; // 7 days

      const jailDurationMs = this.baseJailMs * multiplier;

      return {
        shouldJail: true,
        jailDurationMs,
        totalStrikes: record.strikes,
      };
    }

    return {
      shouldJail: false,
      jailDurationMs: 0,
      totalStrikes: record.strikes,
    };
  }

  public getRecord(ip: string): StrikeRecord | undefined {
    return this.records.get(ip);
  }

  public clear(): void {
    this.records.clear();
  }
}
