'use strict';

const ipStore = new Map();

function cleanupDdosStore(maxIdleMs = 120000) {
  const now = Date.now();
  for (const [ip, rec] of ipStore) {
    if (now - rec.lastSeen > maxIdleMs) {
      ipStore.delete(ip);
    }
  }
}

function checkDdos(ip, config = {}, log = console) {
  const cfg = {
    enabled: true,
    windowMs: 60000,
    maxRequests: 240,
    burstLimit: 60,
    burstWindowMs: 5000,
    penaltyMs: 30000,
    ...config,
  };

  if (!cfg.enabled) return { blocked: false };

  const now = Date.now();
  let rec = ipStore.get(ip) || {
    count: 0,
    burstCount: 0,
    firstSeen: now,
    lastSeen: now,
    burstStart: now,
    violations: 0,
  };

  if (now - rec.firstSeen > cfg.windowMs) {
    rec.count = 0;
    rec.firstSeen = now;
  }

  if (now - rec.burstStart > cfg.burstWindowMs) {
    rec.burstCount = 0;
    rec.burstStart = now;
  }

  rec.count++;
  rec.burstCount++;
  rec.lastSeen = now;
  ipStore.set(ip, rec);

  if (rec.burstCount > cfg.burstLimit) {
    rec.violations++;
    if (log?.threat) {
      log.threat(`DDoS Shield | Burst limit exceeded: ${ip} (${rec.burstCount} req in ${cfg.burstWindowMs}ms)`);
    }
    return {
      blocked: true,
      reason: 'DDoS burst rate limit exceeded',
      layer: 2,
      retryAfter: Math.ceil(cfg.penaltyMs / 1000),
    };
  }

  if (rec.count > cfg.maxRequests) {
    rec.violations++;
    if (log?.warn) {
      log.warn(`DDoS Shield | Rate limit exceeded: ${ip} (${rec.count} req in window)`);
    }
    return {
      blocked: true,
      reason: 'DoS rate limit exceeded',
      layer: 2,
      retryAfter: Math.ceil((rec.firstSeen + cfg.windowMs - now) / 1000),
    };
  }

  return { blocked: false };
}

function getDdosRecord(ip) {
  return ipStore.get(ip) || null;
}

function resetDdosRecord(ip) {
  ipStore.delete(ip);
}

function getDdosStoreSize() {
  return ipStore.size;
}

module.exports = {
  checkDdos,
  getDdosRecord,
  resetDdosRecord,
  getDdosStoreSize,
  cleanupDdosStore,
  ipStore,
};
