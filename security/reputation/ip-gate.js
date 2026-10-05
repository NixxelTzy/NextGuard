'use strict';

const banlist = new Map();

function ipInCIDR(ip, cidr) {
  if (!cidr.includes('/')) return ip === cidr;
  try {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1) >>> 0;
    const ipNum = ip.split('.').reduce((acc, b) => (acc << 8) | parseInt(b, 10), 0) >>> 0;
    const rangeNum = range.split('.').reduce((acc, b) => (acc << 8) | parseInt(b, 10), 0) >>> 0;
    return (ipNum & mask) === (rangeNum & mask);
  } catch {
    return false;
  }
}

function checkIpGate(ip, config = {}, log = console) {
  const cfg = {
    enabled: true,
    staticBlacklist: [],
    autobanOnViolations: 5,
    banDurationMs: 3600000,
    ...config,
  };

  if (!cfg.enabled) return { blocked: false };

  if (banlist.has(ip)) {
    const entry = banlist.get(ip);
    if (entry.until === null || entry.until > Date.now()) {
      if (log?.threat) {
        log.threat(`IP Gate | Banned IP: ${ip} | Reason: ${entry.reason}`);
      }
      return { blocked: true, reason: `IP banned: ${entry.reason}`, layer: 1 };
    } else {
      banlist.delete(ip);
    }
  }

  for (const cidr of cfg.staticBlacklist) {
    if (ipInCIDR(ip, cidr)) {
      if (log?.threat) {
        log.threat(`IP Gate | Static blacklist hit: ${ip} matches ${cidr}`);
      }
      banlist.set(ip, { until: null, reason: 'static-blacklist' });
      return { blocked: true, reason: 'IP in static blacklist', layer: 1 };
    }
  }

  return { blocked: false };
}

function banIp(ip, { durationMs = null, reason = 'manual' } = {}) {
  banlist.set(ip, {
    until: durationMs ? Date.now() + durationMs : null,
    reason,
  });
}

function unbanIp(ip) {
  banlist.delete(ip);
}

function getBannedCount() {
  return banlist.size;
}

function cleanupBanlist() {
  const now = Date.now();
  for (const [ip, entry] of banlist) {
    if (entry.until !== null && entry.until < now) {
      banlist.delete(ip);
    }
  }
}

module.exports = {
  checkIpGate,
  ipInCIDR,
  banIp,
  unbanIp,
  getBannedCount,
  cleanupBanlist,
  banlist,
};
