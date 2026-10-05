'use strict';

const SQLI_PATTERNS = [
  /(\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT|SELECT\s+.*?\s+FROM|INSERT\s+INTO\s+.*?\s+VALUES|DELETE\s+FROM|DROP\s+TABLE|DROP\s+DATABASE|ALTER\s+TABLE)\b)/gi,
  /('|")\s*(OR|AND)\s*('|"|\d)\s*(=|LIKE|IS)/gi,
  /;\s*(DROP|ALTER|TRUNCATE|DELETE\s+FROM)\s+/gi,
  /\/\*.*?\*\//g,
  /xp_cmdshell/gi,
  /information_schema\./gi,
  /sys\.tables/gi,
  /benchmark\s*\(\s*\d+\s*,/gi,
  /sleep\s*\(\s*\d+\s*\)/gi,
  /waitfor\s+delay\s+['"]/gi,
  /load_file\s*\(/gi,
  /into\s+outfile\s+['"]/gi,
];

function checkSqlInjection(value) {
  if (!value || typeof value !== 'string') return { matched: false, pattern: null };
  const decoded = (() => {
    try { return decodeURIComponent(value); } catch { return value; }
  })();

  for (const pattern of SQLI_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(decoded) || pattern.test(value)) {
      return { matched: true, pattern: pattern.toString() };
    }
  }
  return { matched: false, pattern: null };
}

module.exports = {
  checkSqlInjection,
  SQLI_PATTERNS,
};
