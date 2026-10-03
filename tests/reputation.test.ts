import { describe, it, expect, beforeEach } from 'vitest';
import { ReputationEngine } from '../src/core/reputation.js';

describe('ReputationEngine (Adaptive Strike & Escalating Jail)', () => {
  let rep: ReputationEngine;

  beforeEach(() => {
    rep = new ReputationEngine({
      enabled: true,
      maxStrikes: 5,
      baseJailMs: 15 * 60 * 1000,
    } as any);
  });

  it('should accumulate strikes for mild threats without immediate jail', () => {
    const res1 = rep.addStrike('1.2.3.4', 'bad_bot'); // +2 strikes
    expect(res1.shouldJail).toBe(false);
    expect(res1.totalStrikes).toBe(2);

    const res2 = rep.addStrike('1.2.3.4', 'rate_limit_exceeded'); // +1 strike = 3
    expect(res2.shouldJail).toBe(false);
    expect(res2.totalStrikes).toBe(3);
  });

  it('should trigger jail once strikes reach maxStrikes', () => {
    rep.addStrike('1.2.3.4', 'sql_injection'); // +3
    const res = rep.addStrike('1.2.3.4', 'xss'); // +3 => total 6 >= 5

    expect(res.shouldJail).toBe(true);
    expect(res.jailDurationMs).toBe(15 * 60 * 1000); // 15 mins for 1st offense
  });

  it('should immediately jail on critical threats (e.g. command_injection or honeypot)', () => {
    const res = rep.addStrike('5.6.7.8', 'command_injection'); // +5 strikes immediately!
    expect(res.shouldJail).toBe(true);
    expect(res.jailDurationMs).toBe(15 * 60 * 1000);
  });

  it('should escalate penalty duration for repeat offenders', () => {
    const ip = '9.9.9.9';

    // 1st jail
    const jail1 = rep.addStrike(ip, 'command_injection');
    expect(jail1.shouldJail).toBe(true);
    expect(jail1.jailDurationMs).toBe(15 * 60 * 1000); // 15 mins

    // 2nd offense
    const jail2 = rep.addStrike(ip, 'command_injection');
    expect(jail2.shouldJail).toBe(true);
    expect(jail2.jailDurationMs).toBe(15 * 60 * 1000 * 8); // 2 hours

    // 3rd offense
    const jail3 = rep.addStrike(ip, 'command_injection');
    expect(jail3.shouldJail).toBe(true);
    expect(jail3.jailDurationMs).toBe(15 * 60 * 1000 * 96); // 24 hours
  });
});
