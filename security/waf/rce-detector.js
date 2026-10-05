'use strict';

const RCE_PATTERNS = [
  /[;&|`$]\s*(cat\s+\/etc\/|wget\s+http|curl\s+http|bash\s+-i|powershell\s+-enc|nc\s+-e|netcat\s+-e)/gi,
  /\$\(\s*(cat|ls|id|whoami|uname|curl|wget)\b/gi,
  /`\s*(cat|ls|id|whoami|uname|curl|wget)\b/gi,
];

function checkRce(value) {
  if (!value || typeof value !== 'string') return { matched: false, pattern: null };
  const decoded = (() => {
    try { return decodeURIComponent(value); } catch { return value; }
  })();

  for (const pattern of RCE_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(decoded) || pattern.test(value)) {
      return { matched: true, pattern: pattern.toString() };
    }
  }
  return { matched: false, pattern: null };
}

module.exports = {
  checkRce,
  RCE_PATTERNS,
};
