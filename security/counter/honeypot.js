'use strict';

const DEFAULT_HONEYPOT_PATHS = [
  '/.env',
  '/.git/head',
  '/wp-config.php',
  '/phpmyadmin',
  '/backup.sql',
  '/db.sql',
  '/.aws/credentials',
];

function isHoneypotPath(url, honeypotPaths = DEFAULT_HONEYPOT_PATHS) {
  if (!honeypotPaths || !Array.isArray(honeypotPaths) || honeypotPaths.length === 0) return false;
  const path = (url.split('?')[0] || '').toLowerCase();
  return honeypotPaths.some((p) => {
    const target = (p || '').toLowerCase();
    if (!target) return false;
    return path === target || path.startsWith(target.endsWith('/') ? target : target + '/');
  });
}

module.exports = {
  isHoneypotPath,
  DEFAULT_HONEYPOT_PATHS,
};
