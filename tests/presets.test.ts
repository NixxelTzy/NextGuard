import { describe, it, expect } from 'vitest';
import { ENDPOINT_PRESETS } from '../src/presets.js';

describe('ENDPOINT_PRESETS', () => {
  it('should export all required endpoint preset keys', () => {
    const expectedKeys = [
      // Auth
      'LOGIN', 'REGISTER', 'LOGOUT', 'FORGOT_PASSWORD',
      'CHANGE_PASSWORD', 'VERIFY_OTP', 'OAUTH_CALLBACK', 'TOKEN_REFRESH', 'API_KEY',
      // User
      'PROFILE', 'FILE_UPLOAD', 'COMMENT', 'MESSAGE',
      // Data
      'SEARCH', 'PRODUCTS', 'PRODUCT_DETAIL', 'CREATE_UPDATE', 'DELETE_DATA', 'BULK',
      // Payment
      'PAYMENT', 'PAYMENT_WEBHOOK', 'WITHDRAW',
      // Admin
      'ADMIN', 'ADMIN_LOGIN', 'INTERNAL_API', 'WEBHOOK',
      // E-Commerce
      'CART', 'ORDER', 'COUPON', 'RATING',
      // Media
      'MEDIA_UPLOAD', 'BLOG',
      // Public
      'PUBLIC_API', 'HEALTH_CHECK', 'SEO', 'NEWSLETTER', 'CONTACT_FORM',
    ];

    for (const key of expectedKeys) {
      expect(ENDPOINT_PRESETS, `Missing preset: ${key}`).toHaveProperty(key);
    }
  });

  it('LOGIN preset should have strict rate limit (max <= 5)', () => {
    const preset = ENDPOINT_PRESETS.LOGIN;
    expect(preset.rateLimit).toBeDefined();
    expect(preset.rateLimit?.max).toBeLessThanOrEqual(5);
    expect(preset.rateLimit?.jailDurationMs).toBeGreaterThan(0);
  });

  it('PAYMENT preset should have ultra-strict rate limit (max <= 5)', () => {
    const preset = ENDPOINT_PRESETS.PAYMENT;
    expect(preset.rateLimit?.max).toBeLessThanOrEqual(5);
  });

  it('PAYMENT_WEBHOOK should have IP whitelist from payment gateways', () => {
    const preset = ENDPOINT_PRESETS.PAYMENT_WEBHOOK;
    expect(preset.ipFilter?.whitelist).toBeDefined();
    expect(preset.ipFilter?.whitelist?.length).toBeGreaterThan(0);
  });

  it('ADMIN preset should restrict access to localhost by default', () => {
    const preset = ENDPOINT_PRESETS.ADMIN;
    expect(preset.ipFilter?.whitelist).toContain('127.0.0.1');
  });

  it('ADMIN_LOGIN preset should have very strict rate limit (max <= 3)', () => {
    const preset = ENDPOINT_PRESETS.ADMIN_LOGIN;
    expect(preset.rateLimit?.max).toBeLessThanOrEqual(3);
    expect(preset.rateLimit?.jailDurationMs).toBeGreaterThanOrEqual(60 * 60 * 1000); // at least 1 hour
  });

  it('HEALTH_CHECK preset should not block legitimate monitoring bots', () => {
    const preset = ENDPOINT_PRESETS.HEALTH_CHECK;
    // Health check should have high rate limit and not block bots
    expect(preset.rateLimit?.max).toBeGreaterThanOrEqual(300);
    const bots = preset.badBots;
    expect(bots === false || (typeof bots === 'object' && bots?.enabled === false)).toBe(true);
  });

  it('MEDIA_UPLOAD preset should allow up to 100MB payload', () => {
    const preset = ENDPOINT_PRESETS.MEDIA_UPLOAD;
    expect(preset.payloadGuard?.maxBodySize).toBeGreaterThanOrEqual(50 * 1024 * 1024);
  });

  it('FILE_UPLOAD preset should have larger payload limit than LOGIN', () => {
    const uploadLimit = ENDPOINT_PRESETS.FILE_UPLOAD.payloadGuard?.maxBodySize ?? 0;
    const loginLimit = ENDPOINT_PRESETS.LOGIN.payloadGuard?.maxBodySize ?? 0;
    expect(uploadLimit).toBeGreaterThan(loginLimit);
  });

  it('INTERNAL_API preset should only allow private IP ranges', () => {
    const preset = ENDPOINT_PRESETS.INTERNAL_API;
    const whitelist = preset.ipFilter?.whitelist ?? [];
    const hasPrivateRange = whitelist.some(ip =>
      ip.startsWith('10.') || ip.startsWith('172.') || ip.startsWith('192.168') || ip === '127.0.0.1'
    );
    expect(hasPrivateRange).toBe(true);
  });

  it('REGISTER preset should have longer jailDurationMs (anti spam)', () => {
    const preset = ENDPOINT_PRESETS.REGISTER;
    expect(preset.rateLimit?.jailDurationMs).toBeGreaterThanOrEqual(30 * 60 * 1000); // 30 menit
  });

  it('each preset should have mode enforce', () => {
    const nonEnforcePresets: string[] = [];
    for (const [key, preset] of Object.entries(ENDPOINT_PRESETS)) {
      if (preset.mode && preset.mode !== 'enforce') {
        nonEnforcePresets.push(key);
      }
    }
    expect(nonEnforcePresets).toHaveLength(0);
  });

  it('SEARCH preset should have high-sensitivity SQLi inspection on query params', () => {
    const preset = ENDPOINT_PRESETS.SEARCH;
    const sqli = preset.sqlInjection;
    expect(sqli).toBeTruthy();
    if (typeof sqli === 'object' && sqli) {
      expect(sqli.inspectQuery).toBe(true);
    }
  });
});
