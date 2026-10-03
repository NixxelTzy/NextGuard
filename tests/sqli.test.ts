import { describe, it, expect } from 'vitest';
import { SQLInjectionDetector } from '../src/core/detectors/sqli.js';

describe('SQLInjectionDetector', () => {
  const detector = new SQLInjectionDetector({ sensitivity: 'medium' });

  it('should detect classic tautology bypass: 1=1', () => {
    const payloads = [
      "' OR 1=1 --",
      "' OR '1'='1",
      "admin' --",
      '" OR ""="',
      "1' OR 'a'='a",
      "1 OR 1=1",
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect UNION based attacks', () => {
    const payloads = [
      "' UNION SELECT null, username, password FROM users --",
      "1 UNION ALL SELECT 1, 2, 3",
      "UNION SELECT * FROM accounts",
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect stacked destructive queries', () => {
    const payloads = [
      "; DROP TABLE users; --",
      "; DELETE FROM products WHERE 1=1",
      "1; TRUNCATE TABLE logs",
      "1; INSERT INTO admins VALUES ('hacker')",
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect time-based blind SQLi functions', () => {
    const payloads = [
      "1' AND SLEEP(5) --",
      "BENCHMARK(50000000,MD5(1))",
      "WAITFOR DELAY '0:0:5'",
      "pg_sleep(10)",
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect schema extraction attempts', () => {
    const payloads = [
      "' UNION SELECT table_name FROM information_schema.tables --",
      "SELECT * FROM sys.tables",
      "SELECT * FROM sqlite_master",
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect SQLi inside nested JSON body', () => {
    const body = {
      user: {
        filter: {
          search: "' OR 1=1 --",
        },
      },
    };

    const result = detector.detectObject(body);
    expect(result.detected).toBe(true);
    expect(result.parameter).toBe('user.filter.search');
  });

  it('should allow legitimate user input', () => {
    const safeInputs = [
      'John Doe',
      'john.doe@example.com',
      'Welcome to my store!',
      'Search for iPhone 15 Pro',
      'SELECT brand: Apple or Samsung',
      'The book title is "Romeo and Juliet"',
      'Order #12345',
    ];

    for (const input of safeInputs) {
      const result = detector.detectValue(input);
      expect(result.detected, `Safe input falsely flagged: ${input}`).toBe(false);
    }
  });
});
