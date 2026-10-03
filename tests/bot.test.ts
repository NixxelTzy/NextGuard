import { describe, it, expect } from 'vitest';
import { BotDetector } from '../src/core/detectors/bot.js';

describe('BotDetector', () => {
  const detector = new BotDetector({ blockEmptyUserAgent: true });

  it('should detect known security scanners and exploit tools', () => {
    const maliciousUAs = [
      'sqlmap/1.4.7#stable (http://sqlmap.org)',
      'Mozilla/5.0 (compatible; Nikto 2.1.6)',
      'Acunetix-Aspect/1.0',
      'dirbuster/1.0',
      'gobuster 3.1.0',
      'Nmap Scripting Engine',
      'nuclei - v2.9.0',
      'Wfuzz/3.1.0',
      'WPScan v3.8.20',
    ];

    for (const ua of maliciousUAs) {
      const result = detector.detectUserAgent(ua);
      expect(result.detected, `Scanner not detected: ${ua}`).toBe(true);
    }
  });

  it('should block empty User-Agent if configured', () => {
    expect(detector.detectUserAgent('').detected).toBe(true);
    expect(detector.detectUserAgent(undefined).detected).toBe(true);
  });

  it('should allow legitimate browser user agents', () => {
    const safeUAs = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
      'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
    ];

    for (const ua of safeUAs) {
      const result = detector.detectUserAgent(ua);
      expect(result.detected, `Legit UA falsely blocked: ${ua}`).toBe(false);
    }
  });

  it('should allow whitelisted search engine bots', () => {
    const searchBots = [
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
      'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
    ];

    for (const bot of searchBots) {
      const result = detector.detectUserAgent(bot);
      expect(result.detected, `Whitelisted bot blocked: ${bot}`).toBe(false);
    }
  });
});
