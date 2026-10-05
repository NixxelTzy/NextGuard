'use strict';

const { checkSqlInjection, SQLI_PATTERNS } = require('./sqli-detector');
const { checkXss, XSS_PATTERNS } = require('./xss-detector');
const { checkRce, RCE_PATTERNS } = require('./rce-detector');
const { checkPathTraversal, PATH_TRAVERSAL_PATTERNS } = require('./path-traversal');

const ALL_ATTACK_SIGNATURES = [
  ...SQLI_PATTERNS,
  ...XSS_PATTERNS,
  ...RCE_PATTERNS,
  ...PATH_TRAVERSAL_PATTERNS,
];

function inspectValue(value) {
  if (!value || typeof value !== 'string') return { matched: false, pattern: null };
  const decoded = (() => {
    try { return decodeURIComponent(value); } catch { return value; }
  })();

  for (const pattern of ALL_ATTACK_SIGNATURES) {
    pattern.lastIndex = 0;
    if (pattern.test(decoded) || pattern.test(value)) {
      return { matched: true, pattern: pattern.toString() };
    }
  }
  return { matched: false, pattern: null };
}

const SAFE_BODY_FIELDS = new Set([
  'password',
  'confirmpassword',
  'currentpassword',
  'newpassword',
  'oldpassword',
  'token',
  'accesstoken',
  'refreshtoken',
  'csrftoken',
  '_csrf',
  'signature',
  'hash',
  'secret',
  'credential',
  'code',
  'authcode',
  'session',
]);

function deepInspect(obj, path = '') {
  if (typeof obj === 'string') {
    const fieldName = (path.split('.').pop() || '').replace(/[\[\]0-9]/g, '').toLowerCase();
    if (SAFE_BODY_FIELDS.has(fieldName)) {
      return { matched: false, pattern: null, path: null };
    }
    const r = inspectValue(obj);
    return { ...r, path };
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const r = deepInspect(obj[i], `${path}[${i}]`);
      if (r.matched) return r;
    }
  } else if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      const fieldName = k.toLowerCase().replace(/[-_]/g, '');
      if (SAFE_BODY_FIELDS.has(fieldName)) {
        continue;
      }
      const r = deepInspect(v, path ? `${path}.${k}` : k);
      if (r.matched) return r;
    }
  }
  return { matched: false, pattern: null, path: null };
}

module.exports = {
  checkSqlInjection,
  checkXss,
  checkRce,
  checkPathTraversal,
  inspectValue,
  deepInspect,
  ALL_ATTACK_SIGNATURES,
  SAFE_BODY_FIELDS,
};
