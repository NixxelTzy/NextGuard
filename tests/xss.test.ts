import { describe, it, expect } from 'vitest';
import { XSSDetector } from '../src/core/detectors/xss.js';

describe('XSSDetector', () => {
  const detector = new XSSDetector({ sensitivity: 'medium' });

  it('should detect direct script tags', () => {
    const payloads = [
      '<script>alert("XSS")</script>',
      '<script src="https://evil.com/payload.js"></script>',
      '</script><script>alert(1)</script>',
      '<SCRIPT>alert(1)</SCRIPT>',
      '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect inline event handlers', () => {
    const payloads = [
      '<img src="x" onerror="alert(1)">',
      '<svg onload="alert(1)">',
      '<body onload=alert("XSS")>',
      '" onfocus="alert(1)" autofocus="',
      '<input type="text" onmouseover="alert(1)">',
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect javascript: URI protocol', () => {
    const payloads = [
      '<a href="javascript:alert(1)">Click here</a>',
      'javascript:alert(document.cookie)',
      '<iframe src="javascript:alert(1)"></iframe>',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect dangerous injection tags', () => {
    const payloads = [
      '<iframe src="https://malicious.com"></iframe>',
      '<object data="evil.swf"></object>',
      '<embed src="evil.swf">',
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect XSS in deep objects', () => {
    const body = {
      comment: {
        author: 'Guest',
        content: '<img src=x onerror=alert(1)>',
      },
    };

    const result = detector.detectObject(body);
    expect(result.detected).toBe(true);
    expect(result.parameter).toBe('comment.content');
  });

  it('should allow clean legitimate inputs', () => {
    const safeInputs = [
      'Hello world!',
      'This is a regular message with 5 > 3 and 2 < 4 comparisons.',
      'Check out https://google.com for more info.',
      'My name is O\'Connor & Sons.',
      'Price: $19.99',
    ];

    for (const input of safeInputs) {
      const result = detector.detectValue(input);
      expect(result.detected, `Safe input falsely flagged: ${input}`).toBe(false);
    }
  });
});
