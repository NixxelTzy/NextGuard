'use strict';

const tarpitStore = new Map();

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function sendTarpit(res, delayMs, slowReadChunkMs, log) {
  if (!res || res.headersSent || res.writableEnded) return;
  try {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Transfer-Encoding', 'chunked');
    res.statusCode = 200;
    res.write('<!DOCTYPE html><html><head><title>Loading...</title></head><body>');
    const end = Date.now() + delayMs;
    while (Date.now() < end && !res.writableEnded) {
      await sleep(slowReadChunkMs);
      if (!res.writableEnded) res.write(' ');
    }
  } finally {
    if (!res.writableEnded) res.end('</body></html>');
  }
}

function getTarpitUntil(ip) {
  return tarpitStore.get(ip) || null;
}

function setTarpit(ip, untilTimestamp) {
  tarpitStore.set(ip, untilTimestamp);
}

function clearTarpit(ip) {
  tarpitStore.delete(ip);
}

function cleanupTarpitStore() {
  const now = Date.now();
  for (const [ip, until] of tarpitStore) {
    if (until < now) tarpitStore.delete(ip);
  }
}

module.exports = {
  sendTarpit,
  getTarpitUntil,
  setTarpit,
  clearTarpit,
  cleanupTarpitStore,
  tarpitStore,
  sleep,
};
