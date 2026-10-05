'use strict';

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//g,
  /\.\.%2[fF]/g,
  /%252[eE]%252[eE]%252[fF]/g,
  /\/etc\/passwd/gi,
  /\/proc\/self\/environ/gi,
  /\/windows\/system32\//gi,
  /c:\\windows\\system32/gi,
];

function checkPathTraversal(value) {
  if (!value || typeof value !== 'string') return { matched: false, pattern: null };
  const decoded = (() => {
    try { return decodeURIComponent(value); } catch { return value; }
  })();

  for (const pattern of PATH_TRAVERSAL_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(decoded) || pattern.test(value)) {
      return { matched: true, pattern: pattern.toString() };
    }
  }
  return { matched: false, pattern: null };
}

module.exports = {
  checkPathTraversal,
  PATH_TRAVERSAL_PATTERNS,
};
