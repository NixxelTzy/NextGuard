'use strict';

const https = require('https');

const telegramCooldown = new Map();

function escapeTelegramHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function sendTelegramAlert(threatInfo, config = {}, log = console) {
  const tg = config?.telegram || {};
  const botToken = tg.botToken || (typeof process !== 'undefined' ? (process.env.TELEGRAM_BOT_TOKEN || process.env.NEXTGUARD_TELEGRAM_TOKEN) : null);
  const chatId = tg.chatId || (typeof process !== 'undefined' ? (process.env.TELEGRAM_CHAT_ID || process.env.NEXTGUARD_TELEGRAM_CHAT_ID) : null);

  const isEnabled = tg.enabled === true || (tg.enabled !== false && Boolean(botToken && chatId));
  if (!isEnabled || !botToken || !chatId) return false;

  const minLayer = tg.minLayer ?? 1;
  if ((threatInfo.layer ?? 1) < minLayer) return false;

  const cooldownMs = tg.cooldownMs ?? 30000;
  const key = `${threatInfo.ip || 'unknown'}:${threatInfo.layer || 0}`;
  const now = Date.now();
  const lastAlert = telegramCooldown.get(key) || 0;
  if (now - lastAlert < cooldownMs) {
    return false;
  }
  telegramCooldown.set(key, now);

  const message = [
    `🛡️ <b>[NextGuard] Security Alert</b>`,
    `🧱 <b>Layer:</b> Layer ${threatInfo.layer || 'Unknown'}`,
    `⚠️ <b>Threat:</b> ${escapeTelegramHtml(threatInfo.reason || 'Attack detected')}`,
    `🌐 <b>Target Path:</b> <code>${escapeTelegramHtml(threatInfo.path || '/')}</code>`,
    `📍 <b>Attacker IP:</b> <code>${escapeTelegramHtml(threatInfo.ip || '0.0.0.0')}</code>`,
    `📱 <b>Method:</b> ${escapeTelegramHtml(threatInfo.method || 'GET')}`,
    `⚡ <b>Action:</b> ${escapeTelegramHtml(threatInfo.action || 'BLOCKED')}`,
    `⏰ <b>Timestamp:</b> ${new Date().toISOString()}`,
  ].join('\n');

  const payload = {
    chat_id: chatId,
    text: message,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  };

  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

  try {
    if (typeof fetch === 'function') {
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      return true;
    } else {
      const postData = JSON.stringify(payload);
      const parsedUrl = new URL(url);
      const req = https.request({
        hostname: parsedUrl.hostname,
        port: 443,
        path: parsedUrl.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
        timeout: 4000,
      });
      req.on('error', (err) => log?.debug?.('Telegram alert error:', err.message));
      req.write(postData);
      req.end();
      return true;
    }
  } catch (err) {
    log?.debug?.('Telegram notification failed:', err.message);
    return false;
  }
}

function cleanupTelegramCooldown() {
  const now = Date.now();
  for (const [k, time] of telegramCooldown) {
    if (now - time > 120000) telegramCooldown.delete(k);
  }
}

module.exports = {
  sendTelegramAlert,
  escapeTelegramHtml,
  cleanupTelegramCooldown,
  telegramCooldown,
};
