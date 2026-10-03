import { describe, it, expect } from 'vitest';
import { IPFilter } from '../src/core/ip-filter.js';

describe('IPFilter & Subnet/CIDR Matching', () => {
  const ipFilter = new IPFilter({
    whitelist: ['127.0.0.1', '10.0.0.0/8'],
    blacklist: ['192.168.1.50', '203.0.113.0/24'],
  });

  it('should match single whitelisted IP', () => {
    expect(ipFilter.isWhitelisted('127.0.0.1')).toBe(true);
    expect(ipFilter.isWhitelisted('127.0.0.2')).toBe(false);
  });

  it('should match CIDR whitelisted range (10.0.0.0/8)', () => {
    expect(ipFilter.isWhitelisted('10.0.0.1')).toBe(true);
    expect(ipFilter.isWhitelisted('10.254.12.99')).toBe(true);
    expect(ipFilter.isWhitelisted('11.0.0.1')).toBe(false);
  });

  it('should match single blacklisted IP', () => {
    expect(ipFilter.isBlacklisted('192.168.1.50')).toBe(true);
    expect(ipFilter.isBlacklisted('192.168.1.51')).toBe(false);
  });

  it('should match CIDR blacklisted range (203.0.113.0/24)', () => {
    expect(ipFilter.isBlacklisted('203.0.113.1')).toBe(true);
    expect(ipFilter.isBlacklisted('203.0.113.254')).toBe(true);
    expect(ipFilter.isBlacklisted('203.0.114.1')).toBe(false);
  });

  it('should resolve client IP correctly from proxy headers', () => {
    const headers = {
      'cf-connecting-ip': '198.51.100.42',
      'x-forwarded-for': '198.51.100.42, 10.0.0.1',
    };
    const ip = ipFilter.resolveClientIp(headers, '127.0.0.1');
    expect(ip).toBe('198.51.100.42');
  });
});
