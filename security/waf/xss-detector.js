'use strict';

const XSS_PATTERNS = [
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript\s*:\s*[a-z0-9_]/gi,
  /on(error|load|click|mouseover|focus|submit)\s*=\s*["']?.*?["']?/gi,
  /<\s*iframe[\s\S]*?>/gi,
  /<\s*object[\s\S]*?>/gi,
  /<\s*embed[\s\S]*?>/gi,
  /document\.cookie/gi,
  /document\.write\s*\(/gi,
  /window\.location\s*=/gi,
  /String\.fromCharCode\s*\(/gi,
  /&#x[0-9a-f]+;/gi,
];

function checkXss(value) {
  if (!value || typeof value !== 'string') return { matched: false, pattern: null };
  const decoded = (() => {
    try { return decodeURIComponent(value); } catch { return value; }
  })();

  for (const pattern of XSS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(decoded) || pattern.test(value)) {
      return { matched: true, pattern: pattern.toString() };
    }
  }
  return { matched: false, pattern: null };
}

module.exports = {
  checkXss,
  XSS_PATTERNS,
};
