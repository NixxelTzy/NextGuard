import { describe, it, expect } from 'vitest';
import { NoSQLInjectionDetector } from '../src/core/detectors/nosqli.js';

describe('NoSQLInjectionDetector', () => {
  const detector = new NoSQLInjectionDetector();

  it('should detect MongoDB operator keys in objects ($gt, $ne, $where)', () => {
    const payloads = [
      { username: 'admin', password: { $gt: '' } },
      { id: { $ne: null } },
      { $where: 'this.password.length > 5' },
      { role: { $in: ['admin', 'root'] } },
      { email: { $regex: '^admin' } },
    ];

    for (const payload of payloads) {
      const result = detector.detectObject(payload);
      expect(result.detected, `Failed to detect payload: ${JSON.stringify(payload)}`).toBe(true);
    }
  });

  it('should detect stringified NoSQL operator injections', () => {
    const stringPayloads = [
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$where": "sleep(5000)"}',
      'db.users.find()',
    ];

    for (const str of stringPayloads) {
      const result = detector.detectValue(str);
      expect(result.detected, `Failed on string: ${str}`).toBe(true);
    }
  });

  it('should allow legitimate clean data without operators', () => {
    const cleanInputs = [
      { username: 'john_doe', password: 'SuperSecretPassword123!' },
      { title: 'Learn MongoDB with Node.js', price: 99.99 },
      { search: 'laptops under $1000' },
      'The price is $50 USD',
    ];

    for (const input of cleanInputs) {
      const result = typeof input === 'object' ? detector.detectObject(input) : detector.detectValue(input);
      expect(result.detected, `Falsely flagged clean input: ${JSON.stringify(input)}`).toBe(false);
    }
  });
});
