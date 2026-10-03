import { describe, it, expect } from 'vitest';
import { SSRFDetector } from '../src/core/detectors/ssrf.js';

describe('SSRFDetector', () => {
  const detector = new SSRFDetector();

  it('should detect cloud metadata endpoint targets (169.254.169.254)', () => {
    const payloads = [
      'http://169.254.169.254/latest/meta-data/',
      'https://169.254.169.254/computeMetadata/v1/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://100.100.100.200/latest/meta-data/',
    ];

    for (const p of payloads) {
      const result = detector.detectValue(p);
      expect(result.detected, `Failed to detect cloud metadata target: ${p}`).toBe(true);
    }
  });

  it('should detect loopback and internal private addresses', () => {
    const payloads = [
      'http://127.0.0.1:8080/admin',
      'http://localhost:3000',
      'http://0.0.0.0/',
      'http://[::1]/internal',
      'http://192.168.1.1/router',
      'http://10.0.0.5/api',
      'http://172.16.0.1/private',
    ];

    for (const p of payloads) {
      const result = detector.detectValue(p);
      expect(result.detected, `Failed to detect loopback/internal target: ${p}`).toBe(true);
    }
  });

  it('should detect dangerous non-HTTP schemes', () => {
    const payloads = [
      'file:///etc/passwd',
      'gopher://127.0.0.1:6379/_flushall',
      'dict://127.0.0.1:11211/stat',
    ];

    for (const p of payloads) {
      const result = detector.detectValue(p);
      expect(result.detected, `Failed to detect scheme: ${p}`).toBe(true);
    }
  });

  it('should allow legitimate public URLs', () => {
    const safeUrls = [
      'https://api.github.com/users',
      'https://images.unsplash.com/photo-1234.jpg',
      'https://example.com/webhook',
    ];

    for (const url of safeUrls) {
      expect(detector.detectValue(url).detected).toBe(false);
    }
  });
});
