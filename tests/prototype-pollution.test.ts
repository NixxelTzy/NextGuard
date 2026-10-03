import { describe, it, expect } from 'vitest';
import { PrototypePollutionDetector } from '../src/core/detectors/prototype-pollution.js';

describe('PrototypePollutionDetector', () => {
  const detector = new PrototypePollutionDetector();

  it('should detect __proto__ in object keys', () => {
    // Note: Use Object.create to create payload with __proto__ as an own property
    const payload = JSON.parse('{"__proto__": {"isAdmin": true}}');
    const result = detector.detectObject(payload);
    expect(result.detected).toBe(true);
  });

  it('should detect constructor.prototype in keys or strings', () => {
    const payloads = [
      'constructor.prototype.polluted = true',
      '__proto__.polluted = true',
      '__defineGetter__',
    ];

    for (const p of payloads) {
      const result = detector.detectValue(p);
      expect(result.detected, `Failed to detect prototype pollution: ${p}`).toBe(true);
    }
  });

  it('should detect prototype tampering in nested objects', () => {
    const nested = {
      user: {
        settings: {
          '__proto__.admin': true,
        },
      },
    };

    const result = detector.detectObject(nested);
    expect(result.detected).toBe(true);
  });

  it('should allow legitimate clean objects', () => {
    const safeObject = {
      username: 'alice',
      email: 'alice@example.com',
      profile: {
        theme: 'dark',
        notifications: true,
      },
    };

    expect(detector.detectObject(safeObject).detected).toBe(false);
  });
});
