'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

// src/core/detectors/sqli.ts
var SQLI_PATTERNS = {
  // Boolean-based and tautology attacks: ' OR 1=1, " OR ""=", ' OR 'x'='x
  tautology: [
    /(?:['"]\s*or\s+['"\d\w]+\s*=\s*['"\d\w]+)/i,
    /(?:["']\s*or\s+true\s*--?)/i,
    /(?:\bor\b\s+[\w\d]+\s*=\s*[\w\d]+)/i,
    /(?:\band\b\s+[\w\d]+\s*!=\s*[\w\d]+)/i,
    /(?:\b(?:or|and)\b\s+1\s*=\s*1)/i,
    /(?:\b(?:or|and)\b\s+0\s*=\s*0)/i,
    /(?:\b(?:or|and)\b\s+['"]?1['"]?\s*=\s*['"]?1['"]?)/i,
    /(?:admin['"]\s*(?:--|#|\/\*))/i,
    /(?:['"]\s*or\s*['"]{1,2}\s*=\s*['"]?)/i,
    /(?:['"]\s*or\s*''\s*=\s*')/i,
    /(?:["']\s*or\s*""\s*=\s*")/i
  ],
  // UNION-based attacks: UNION SELECT, UNION ALL SELECT
  union: [
    /(?:\bunion\b(?:\s+all)?\s+\bselect\b)/i,
    /(?:\bunion\b\s+.*?\bselect\b)/i,
    /(?:\bselect\b\s+.*?\bfrom\b\s+.*?\bunion\b)/i
  ],
  // Stacked queries and destructive commands
  destructive: [
    /(?:;\s*(?:drop|truncate|alter|create)\s+(?:table|database|view|index|schema)\b)/i,
    /(?:;\s*(?:insert\s+into|update\s+\w+\s+set|delete\s+from)\b)/i,
    /(?:;\s*shutdown\b)/i,
    /(?:;\s*exec\s+(?:xp_cmdshell|sp_executesql)\b)/i
  ],
  // Time-based blind SQLi functions
  timeBased: [
    /(?:\bsleep\s*\(\s*\d+\s*\))/i,
    /(?:\bbenchmark\s*\(\s*\d+\s*,.*?\))/i,
    /(?:\bwaitfor\s+delay\s+['"]\d+:\d+:\d+['"])/i,
    /(?:\bpg_sleep\s*\(\s*\d+\s*\))/i,
    /(?:\bdbms_pipe\.receive_message\b)/i
  ],
  // Information schema & database metadata harvesting
  schemaExtraction: [
    /(?:\binformation_schema\.(?:tables|columns|schemata|views|user_privileges)\b)/i,
    /(?:\bsys\.(?:tables|databases|all_views)\b)/i,
    /(?:\bsqlite_master\b)/i,
    /(?:\ball_tab_columns\b)/i,
    /(?:\bpg_catalog\b)/i,
    /(?:\bload_file\s*\(.*?\))/i,
    /(?:\binto\s+(?:outfile|dumpfile)\b)/i
  ],
  // Comments and inline obfuscation
  commentsAndSyntax: [
    /(?:(?:\/\*![\d]*|\/\*)[^*]*\*+(?:[^*\/][^*]*\*+)*\/)/i,
    // /*!50000 SELECT */ or multi-line comment tricks
    /(?:'\s*--)/i,
    /(?:;\s*--)/i,
    /(?:'\s*#)/i,
    /(?:'\s*\/\*)/i
  ],
  // High-sensitivity patterns (heuristic)
  highSensitivity: [
    /(?:\bchar\s*\(\s*\d+\s*(?:,\s*\d+\s*)*\))/i,
    /(?:\bconcat\s*\(.*?\bselect\b)/i,
    /(?:\bextractvalue\s*\(.*?\))/i,
    /(?:\bupdatexml\s*\(.*?\))/i,
    /(?:\bxp_cmdshell\b)/i,
    /(?:0x[0-9a-fA-F]{6,})/i,
    // long hex literals
    /(?:\bcast\s*\(.*?\bas\s+(?:char|varchar|integer)\b)/i,
    /(?:\bconvert\s*\(.*?\busing\b)/i
  ]
};
function safeUrlDecode(value) {
  try {
    const once = decodeURIComponent(value);
    try {
      return decodeURIComponent(once);
    } catch {
      return once;
    }
  } catch {
    return value;
  }
}
function normalizeString(input) {
  let normalized = safeUrlDecode(input);
  normalized = normalized.replace(/\0/g, "");
  normalized = normalized.replace(/\/\*.*?\*\//g, " ");
  normalized = normalized.replace(/\s+/g, " ").trim();
  return normalized;
}
var SQLInjectionDetector = class {
  patterns = [];
  excludePatterns = [];
  sensitivity = "medium";
  constructor(config) {
    this.sensitivity = config?.sensitivity || "medium";
    this.excludePatterns = config?.excludePatterns || [];
    this.patterns.push(
      ...SQLI_PATTERNS.tautology,
      ...SQLI_PATTERNS.union,
      ...SQLI_PATTERNS.destructive,
      ...SQLI_PATTERNS.timeBased
    );
    if (this.sensitivity === "medium" || this.sensitivity === "high") {
      this.patterns.push(
        ...SQLI_PATTERNS.schemaExtraction,
        ...SQLI_PATTERNS.commentsAndSyntax
      );
    }
    if (this.sensitivity === "high") {
      this.patterns.push(...SQLI_PATTERNS.highSensitivity);
    }
    if (config?.customPatterns && config.customPatterns.length > 0) {
      this.patterns.push(...config.customPatterns);
    }
  }
  /**
   * Check a single string value for SQL Injection signatures
   */
  detectValue(val, paramName) {
    if (val === null || val === void 0) {
      return { detected: false };
    }
    if (typeof val === "number" || typeof val === "boolean") {
      return { detected: false };
    }
    let stringVal = "";
    if (typeof val === "string") {
      stringVal = val;
    } else if (typeof val === "object") {
      return this.detectObject(val, paramName);
    } else {
      stringVal = String(val);
    }
    for (const exclude of this.excludePatterns) {
      if (exclude.test(stringVal)) {
        return { detected: false };
      }
    }
    const normalized = normalizeString(stringVal);
    for (const pattern of this.patterns) {
      if (pattern.test(stringVal) || pattern.test(normalized)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: stringVal.length > 100 ? stringVal.slice(0, 100) + "..." : stringVal,
          parameter: paramName
        };
      }
    }
    return { detected: false };
  }
  /**
   * Recursively inspect an object or array (e.g. query params, request body)
   */
  detectObject(obj, prefix = "") {
    if (!obj || typeof obj !== "object") {
      return this.detectValue(obj, prefix);
    }
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const result = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (result.detected) return result;
      }
      return { detected: false };
    }
    for (const [key, value] of Object.entries(obj)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      const keyResult = this.detectValue(key, currentParam);
      if (keyResult.detected) {
        return { ...keyResult, location: "parameter_key" };
      }
      const valResult = this.detectValue(value, currentParam);
      if (valResult.detected) {
        return valResult;
      }
    }
    return { detected: false };
  }
};

// src/core/detectors/nosqli.ts
var NOSQL_OPERATOR_PATTERNS = [
  /^\$(?:where|regex|ne|gt|gte|lt|lte|in|nin|exists|type|mod|all|size|elemMatch|expr|jsonSchema|text|search|or|and|nor|not)\b/i,
  /["']\$(?:where|regex|ne|gt|gte|lt|lte|in|nin|exists|type|mod|all|size|elemMatch|expr|or|and|nor|not)["']\s*:/i,
  /\btojson\s*\(/i,
  /\bmapreduce\s*\(/i,
  /\bdb\.\w+\.(?:find|update|insert|remove|drop)\b/i
];
var NoSQLInjectionDetector = class {
  patterns;
  constructor(config) {
    this.patterns = [...NOSQL_OPERATOR_PATTERNS];
    if (config?.customPatterns) {
      this.patterns.push(...config.customPatterns);
    }
  }
  detectValue(val, paramName) {
    if (val === null || val === void 0) return { detected: false };
    if (typeof val === "number" || typeof val === "boolean") return { detected: false };
    if (typeof val === "object") {
      return this.detectObject(val, paramName);
    }
    const stringVal = String(val);
    for (const pattern of this.patterns) {
      if (pattern.test(stringVal)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: stringVal.length > 100 ? stringVal.slice(0, 100) + "..." : stringVal,
          parameter: paramName
        };
      }
    }
    return { detected: false };
  }
  detectObject(obj, prefix = "") {
    if (!obj || typeof obj !== "object") {
      return this.detectValue(obj, prefix);
    }
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const res = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (res.detected) return res;
      }
      return { detected: false };
    }
    for (const [key, value] of Object.entries(obj)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      if (key.startsWith("$")) {
        for (const pattern of this.patterns) {
          if (pattern.test(key)) {
            return {
              detected: true,
              pattern: pattern.toString(),
              matchedValue: key,
              parameter: currentParam,
              location: "parameter_key"
            };
          }
        }
      }
      const res = this.detectValue(value, currentParam);
      if (res.detected) return res;
    }
    return { detected: false };
  }
};

// src/core/detectors/prototype-pollution.ts
var POLLUTION_KEYS = [
  /(?:^|\.)__proto__(?:\.|$|\[)/,
  /(?:^|\.)constructor\.prototype(?:\.|$|\[)/,
  /(?:^|\.)prototype(?:\.|$|\[)/,
  /__defineGetter__/,
  /__defineSetter__/,
  /__lookupGetter__/,
  /__lookupSetter__/
];
var PrototypePollutionDetector = class {
  constructor(_config) {
  }
  detectValue(val, paramName) {
    if (val === null || val === void 0) return { detected: false };
    if (typeof val === "object") {
      return this.detectObject(val, paramName);
    }
    const str = String(val);
    for (const pattern of POLLUTION_KEYS) {
      if (pattern.test(str)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: str,
          parameter: paramName
        };
      }
    }
    return { detected: false };
  }
  detectObject(obj, prefix = "") {
    if (!obj || typeof obj !== "object") {
      return this.detectValue(obj, prefix);
    }
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const res = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (res.detected) return res;
      }
      return { detected: false };
    }
    for (const [key, value] of Object.entries(obj)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      for (const pattern of POLLUTION_KEYS) {
        if (pattern.test(key) || pattern.test(currentParam)) {
          return {
            detected: true,
            pattern: pattern.toString(),
            matchedValue: key,
            parameter: currentParam,
            location: "parameter_key"
          };
        }
      }
      const res = this.detectValue(value, currentParam);
      if (res.detected) return res;
    }
    return { detected: false };
  }
};

// src/core/detectors/ssrf.ts
var SSRF_PATTERNS = [
  // Cloud metadata services (AWS, GCP, Azure, Alibaba)
  /https?:\/\/169\.254\.169\.254\b/i,
  /https?:\/\/metadata\.google\.internal\b/i,
  /https?:\/\/100\.100\.100\.200\b/i,
  // Loopback addresses
  /https?:\/\/127\.(?:\d{1,3}\.){2}\d{1,3}\b/i,
  /https?:\/\/localhost\b/i,
  /https?:\/\/0\.0\.0\.0(?::\d+|\/|$|\b)/i,
  /https?:\/\/\[::1\](?::\d+|\/|$)/i,
  /https?:\/\/0x7f000001\b/i,
  // hex encoded 127.0.0.1
  /https?:\/\/2130706433\b/i,
  // dword encoded 127.0.0.1
  // Private network ranges (RFC 1918)
  /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/i,
  /https?:\/\/172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b/i,
  /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}\b/i,
  // Dangerous non-HTTP schemes
  /(?:file|gopher|dict|ldap|tftp|sftp):\/\//i
];
var SSRFDetector = class {
  patterns;
  constructor(config) {
    this.patterns = [...SSRF_PATTERNS];
  }
  detectValue(val, paramName) {
    if (val === null || val === void 0) return { detected: false };
    if (typeof val === "number" || typeof val === "boolean") return { detected: false };
    if (typeof val === "object") {
      return this.detectObject(val, paramName);
    }
    const str = String(val);
    let decoded = str;
    try {
      decoded = decodeURIComponent(str);
    } catch {
    }
    for (const pattern of this.patterns) {
      if (pattern.test(str) || pattern.test(decoded)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: str.length > 100 ? str.slice(0, 100) + "..." : str,
          parameter: paramName
        };
      }
    }
    return { detected: false };
  }
  detectObject(obj, prefix = "") {
    if (!obj || typeof obj !== "object") {
      return this.detectValue(obj, prefix);
    }
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const res = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (res.detected) return res;
      }
      return { detected: false };
    }
    for (const [key, value] of Object.entries(obj)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      const res = this.detectValue(value, currentParam);
      if (res.detected) return res;
    }
    return { detected: false };
  }
};

// src/core/detectors/xss.ts
var XSS_PATTERNS = {
  // Direct script tags
  scriptTag: [
    /<\s*script\b[^>]*>[\s\S]*?(?:<\/\s*script\s*>)?/i,
    /<\s*\/\s*script\s*>/i,
    /<\s*script\b/i
  ],
  // Inline DOM event handlers (e.g. onload, onerror, onclick, onmouseover)
  eventHandlers: [
    /\bon(?:load|error|click|dblclick|mouseover|mouseout|mouseenter|mouseleave|mousemove|keydown|keyup|keypress|focus|blur|change|submit|reset|input|contextmenu|drag|drop|scroll|wheel|toggle|pointerdown|pointerup)\s*=\s*['"]?[^'"]*['"]?/i,
    /<[^>]+\bon[a-z]+\s*=/i
  ],
  // Javascript / VBScript / Data URIs in src, href, or attributes
  uriProtocols: [
    /(?:href|src|data|action|formaction)\s*=\s*['"]?\s*javascript\s*:/i,
    /(?:href|src|data|action|formaction)\s*=\s*['"]?\s*vbscript\s*:/i,
    /(?:href|src|data|action|formaction)\s*=\s*['"]?\s*data:\s*text\/html/i,
    /\bdata:\s*text\/html/i,
    /javascript\s*:\s*[^\s]+/i
  ],
  // Dangerous HTML tags typically used for injection: <iframe>, <object>, <embed>, <svg onload>, <img> with onerror
  dangerousTags: [
    /<\s*(?:iframe|object|embed|applet|meta|base|link|form)\b[^>]*>/i,
    /<\s*svg\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*img\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*body\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*audio\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*video\b[^>]*\bon[a-z]+\s*=/i,
    /<\s*style\b[^>]*>[\s\S]*?(?:expression\(|behavior:|url\s*\(\s*['"]?javascript:)/i
  ],
  // JS execution primitives commonly used in evasion
  executionPrimitives: [
    /(?:window|document|top|parent)\s*\[\s*['"][a-z]+['"]\s*\]/i,
    /document\s*\.\s*(?:cookie|location|write|writeln|domain)\b/i,
    /window\s*\.\s*(?:location|eval)\b/i,
    /(?:\beval\b|\bFunction\b|\bsetTimeout\b|\bsetInterval\b)\s*\(\s*['"][^'"]*['"]\s*\)/i
  ]
};
function decodeHtmlEntities(str) {
  return str.replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16))).replace(/&#(\d+);?/g, (_, dec) => String.fromCharCode(parseInt(dec, 10))).replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&quot;/gi, '"').replace(/&apos;/gi, "'").replace(/&amp;/gi, "&");
}
function safeUrlDecode2(value) {
  try {
    const once = decodeURIComponent(value);
    try {
      return decodeURIComponent(once);
    } catch {
      return once;
    }
  } catch {
    return value;
  }
}
var XSSDetector = class {
  patterns = [];
  excludePatterns = [];
  sensitivity = "medium";
  constructor(config) {
    this.sensitivity = config?.sensitivity || "medium";
    this.excludePatterns = config?.excludePatterns || [];
    this.patterns.push(
      ...XSS_PATTERNS.scriptTag,
      ...XSS_PATTERNS.eventHandlers,
      ...XSS_PATTERNS.uriProtocols
    );
    if (this.sensitivity === "medium" || this.sensitivity === "high") {
      this.patterns.push(...XSS_PATTERNS.dangerousTags);
    }
    if (this.sensitivity === "high") {
      this.patterns.push(...XSS_PATTERNS.executionPrimitives);
    }
    if (config?.customPatterns && config.customPatterns.length > 0) {
      this.patterns.push(...config.customPatterns);
    }
  }
  detectValue(val, paramName) {
    if (val === null || val === void 0) {
      return { detected: false };
    }
    if (typeof val === "number" || typeof val === "boolean") {
      return { detected: false };
    }
    let stringVal = "";
    if (typeof val === "string") {
      stringVal = val;
    } else if (typeof val === "object") {
      return this.detectObject(val, paramName);
    } else {
      stringVal = String(val);
    }
    for (const exclude of this.excludePatterns) {
      if (exclude.test(stringVal)) {
        return { detected: false };
      }
    }
    const decodedUrl = safeUrlDecode2(stringVal);
    const decodedHtml = decodeHtmlEntities(decodedUrl);
    for (const pattern of this.patterns) {
      if (pattern.test(stringVal) || pattern.test(decodedUrl) || pattern.test(decodedHtml)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: stringVal.length > 100 ? stringVal.slice(0, 100) + "..." : stringVal,
          parameter: paramName
        };
      }
    }
    return { detected: false };
  }
  detectObject(obj, prefix = "") {
    if (!obj || typeof obj !== "object") {
      return this.detectValue(obj, prefix);
    }
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const result = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (result.detected) return result;
      }
      return { detected: false };
    }
    for (const [key, value] of Object.entries(obj)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      const keyResult = this.detectValue(key, currentParam);
      if (keyResult.detected) {
        return { ...keyResult, location: "parameter_key" };
      }
      const valResult = this.detectValue(value, currentParam);
      if (valResult.detected) {
        return valResult;
      }
    }
    return { detected: false };
  }
};

// src/core/detectors/command-injection.ts
var COMMAND_INJECTION_PATTERNS = [
  // Command chaining with common recon/malicious commands
  /(?:[;&|`]\s*(?:cat|more|less|tail|head)\s+(?:\/etc\/|\/var\/|\/tmp\/|[a-zA-Z]:\\))/i,
  /(?:[;&|`]\s*(?:id|whoami|uname\s+-a|hostname|ifconfig|ip\s+a)\b)/i,
  /(?:[;&|`]\s*(?:curl|wget|nc|ncat|netcat|bash|sh|zsh|csh)\s+)/i,
  /(?:[;&|`]\s*(?:rm\s+-rf|chmod\s+[0-7]{3,4}|chown\s+))/i,
  /(?:[;&|`]\s*(?:powershell(?:\.exe)?|cmd(?:\.exe)?)\b)/i,
  /(?:[;&|`]\s*(?:systeminfo|net\s+user|net\s+localgroup)\b)/i,
  // Shell substitution syntax
  /\$\(\s*(?:cat|id|whoami|uname|ls|dir|curl|wget|bash|sh|powershell)\b/i,
  /`\s*(?:cat|id|whoami|uname|ls|dir|curl|wget|bash|sh|powershell)\b/i,
  // Direct reverse shell signatures
  /\/bin\/(?:ba)?sh\s+-i/i,
  /\bnc(?:\.traditional)?\s+.*?-e\s+\S+/i,
  /\bnc\s+(?:-[a-zA-Z]*e\s+)?(?:\d{1,3}\.){3}\d{1,3}\s+\d+/i,
  /bash\s+-c\s+['"].*?>&/i,
  // Windows command injection patterns
  /(?:&|&&|\||\|\|)\s*(?:dir|type|copy|del|tasklist|reg\s+query)\b/i
];
var CommandInjectionDetector = class {
  patterns = [];
  constructor(config) {
    this.patterns = [...COMMAND_INJECTION_PATTERNS];
    if (config?.customPatterns) {
      this.patterns.push(...config.customPatterns);
    }
  }
  detectValue(val, paramName) {
    if (val === null || val === void 0) return { detected: false };
    if (typeof val === "number" || typeof val === "boolean") return { detected: false };
    let stringVal = "";
    if (typeof val === "string") {
      stringVal = val;
    } else if (typeof val === "object") {
      return this.detectObject(val, paramName);
    } else {
      stringVal = String(val);
    }
    let decoded = stringVal;
    try {
      decoded = decodeURIComponent(stringVal);
    } catch {
    }
    for (const pattern of this.patterns) {
      if (pattern.test(stringVal) || pattern.test(decoded)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: stringVal.length > 100 ? stringVal.slice(0, 100) + "..." : stringVal,
          parameter: paramName
        };
      }
    }
    return { detected: false };
  }
  detectObject(obj, prefix = "") {
    if (!obj || typeof obj !== "object") {
      return this.detectValue(obj, prefix);
    }
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const result = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (result.detected) return result;
      }
      return { detected: false };
    }
    for (const [key, value] of Object.entries(obj)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      const keyResult = this.detectValue(key, currentParam);
      if (keyResult.detected) return { ...keyResult, location: "parameter_key" };
      const valResult = this.detectValue(value, currentParam);
      if (valResult.detected) return valResult;
    }
    return { detected: false };
  }
};

// src/core/detectors/path-traversal.ts
var PATH_TRAVERSAL_PATTERNS = [
  // Directory traversal sequences (plain, url encoded, double url encoded)
  /(?:\.\.\/|\.\.\\)/,
  /(?:%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|\.\.%5c)/i,
  /(?:%252e%252e%252f|%252e%252e\/)/i,
  // Common sensitive files (Unix/Linux)
  /(?:\/etc\/(?:passwd|shadow|hosts|group|issue|hostname|crontab))/i,
  /(?:\/proc\/(?:self|version|cmdline|environ|net\/tcp))/i,
  /(?:\/var\/log\/(?:apache2|nginx|syslog|auth\.log|messages))/i,
  // Common sensitive files (Windows)
  /(?:[a-zA-Z]:\\(?:windows|winnt)\\(?:system32|repair|win\.ini|system\.ini))/i,
  /(?:boot\.ini|pagefile\.sys)/i,
  // Null byte injection attempt
  /(?:%00|\0)/,
  // PHP wrapper and remote file inclusion schemes
  /(?:php:\/\/(?:input|filter|memory|temp)|data:\/\/text\/plain|expect:\/\/)/i
];
var PathTraversalDetector = class {
  patterns = [];
  constructor(config) {
    this.patterns = [...PATH_TRAVERSAL_PATTERNS];
    if (config?.customPatterns) {
      this.patterns.push(...config.customPatterns);
    }
  }
  detectValue(val, paramName) {
    if (val === null || val === void 0) return { detected: false };
    if (typeof val === "number" || typeof val === "boolean") return { detected: false };
    let stringVal = "";
    if (typeof val === "string") {
      stringVal = val;
    } else if (typeof val === "object") {
      return this.detectObject(val, paramName);
    } else {
      stringVal = String(val);
    }
    let decoded = stringVal;
    try {
      decoded = decodeURIComponent(stringVal);
    } catch {
    }
    for (const pattern of this.patterns) {
      if (pattern.test(stringVal) || pattern.test(decoded)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          matchedValue: stringVal.length > 100 ? stringVal.slice(0, 100) + "..." : stringVal,
          parameter: paramName
        };
      }
    }
    return { detected: false };
  }
  detectObject(obj, prefix = "") {
    if (!obj || typeof obj !== "object") {
      return this.detectValue(obj, prefix);
    }
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        const result = this.detectValue(obj[i], `${prefix}[${i}]`);
        if (result.detected) return result;
      }
      return { detected: false };
    }
    for (const [key, value] of Object.entries(obj)) {
      const currentParam = prefix ? `${prefix}.${key}` : key;
      const keyResult = this.detectValue(key, currentParam);
      if (keyResult.detected) return { ...keyResult, location: "parameter_key" };
      const valResult = this.detectValue(value, currentParam);
      if (valResult.detected) return valResult;
    }
    return { detected: false };
  }
};

// src/core/detectors/bot.ts
var KNOWN_SCANNERS = [
  /sqlmap/i,
  /nikto/i,
  /acunetix/i,
  /dirbuster/i,
  /gobuster/i,
  /ffuf/i,
  /wpscan/i,
  /nmap/i,
  /masscan/i,
  /zgrab/i,
  /censys/i,
  /shodan/i,
  /nessus/i,
  /openvas/i,
  /nuclei/i,
  /hydra/i,
  /metasploit/i,
  /burpcollaborator/i,
  /arachni/i,
  /havij/i,
  /pangolin/i,
  /qualys/i,
  /netsparker/i,
  /appscan/i,
  /wfuzz/i,
  /zaproxy/i
];
var DEFAULT_WHITELIST = [
  /googlebot/i,
  /bingbot/i,
  /slurp/i,
  /duckduckbot/i,
  /baiduspider/i,
  /yandexbot/i,
  /facebot/i,
  /ia_archiver/i,
  /twitterbot/i,
  /linkedinbot/i,
  /slackbot/i,
  /discordbot/i,
  /telegrambot/i,
  /applebot/i
];
var BotDetector = class {
  blockEmpty;
  knownScanners;
  customBlacklist;
  whitelist;
  constructor(config) {
    this.blockEmpty = config?.blockEmptyUserAgent ?? false;
    this.knownScanners = config?.knownScanners ?? true;
    this.customBlacklist = config?.customBlacklist ?? [];
    this.whitelist = config?.whitelist ?? DEFAULT_WHITELIST;
  }
  detectUserAgent(userAgent) {
    if (!userAgent || userAgent.trim() === "") {
      if (this.blockEmpty) {
        return { detected: true, reason: "Empty User-Agent header is blocked" };
      }
      return { detected: false };
    }
    const ua = userAgent.trim();
    for (const allowed of this.whitelist) {
      if (typeof allowed === "string") {
        if (ua.toLowerCase().includes(allowed.toLowerCase())) return { detected: false };
      } else if (allowed instanceof RegExp) {
        if (allowed.test(ua)) return { detected: false };
      }
    }
    for (const blocked of this.customBlacklist) {
      if (typeof blocked === "string") {
        if (ua.toLowerCase().includes(blocked.toLowerCase())) {
          return { detected: true, reason: `User-Agent matches blocked string: ${blocked}` };
        }
      } else if (blocked instanceof RegExp) {
        if (blocked.test(ua)) {
          return { detected: true, reason: `User-Agent matches blocked pattern: ${blocked}` };
        }
      }
    }
    if (this.knownScanners) {
      for (const scanner of KNOWN_SCANNERS) {
        if (scanner.test(ua)) {
          return { detected: true, reason: `Known vulnerability scanner detected: ${scanner.source}` };
        }
      }
    }
    return { detected: false };
  }
};

// src/core/stores/memory-store.ts
var MemoryStore = class {
  map = /* @__PURE__ */ new Map();
  gcInterval = null;
  constructor(gcIntervalMs = 3e4) {
    if (typeof setInterval !== "undefined") {
      this.gcInterval = setInterval(() => this.cleanup(), gcIntervalMs);
      if (this.gcInterval && typeof this.gcInterval.unref === "function") {
        this.gcInterval.unref();
      }
    }
  }
  async increment(key, windowMs) {
    const now = Date.now();
    let entry = this.map.get(key);
    if (!entry || now > entry.resetTime) {
      entry = {
        count: 1,
        resetTime: now + windowMs,
        isJailed: false,
        jailUntil: 0
      };
      this.map.set(key, entry);
      return { count: 1, resetTime: entry.resetTime };
    }
    entry.count += 1;
    return { count: entry.count, resetTime: entry.resetTime };
  }
  async get(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    const now = Date.now();
    if (now > entry.resetTime && (!entry.isJailed || now > entry.jailUntil)) {
      this.map.delete(key);
      return null;
    }
    return {
      count: entry.count,
      resetTime: entry.resetTime,
      isJailed: entry.isJailed && now < entry.jailUntil,
      jailUntil: entry.jailUntil
    };
  }
  async jail(key, durationMs) {
    const now = Date.now();
    const entry = this.map.get(key);
    const jailUntil = now + durationMs;
    if (entry) {
      entry.isJailed = true;
      entry.jailUntil = jailUntil;
    } else {
      this.map.set(key, {
        count: 1,
        resetTime: jailUntil,
        isJailed: true,
        jailUntil
      });
    }
  }
  async isJailed(key) {
    const entry = this.map.get(key);
    if (!entry || !entry.isJailed) return false;
    if (Date.now() > entry.jailUntil) {
      entry.isJailed = false;
      return false;
    }
    return true;
  }
  async reset(key) {
    this.map.delete(key);
  }
  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.map.entries()) {
      if (now > entry.resetTime && (!entry.isJailed || now > entry.jailUntil)) {
        this.map.delete(key);
      }
    }
  }
  destroy() {
    if (this.gcInterval) {
      clearInterval(this.gcInterval);
      this.gcInterval = null;
    }
    this.map.clear();
  }
};

// src/core/rate-limiter.ts
var RateLimiter = class {
  enabled;
  windowMs;
  max;
  jailDurationMs;
  jailThreshold;
  store;
  keyGenerator;
  constructor(config) {
    this.enabled = config?.enabled ?? true;
    this.windowMs = config?.windowMs ?? 6e4;
    this.max = config?.max ?? 100;
    this.jailDurationMs = config?.jailDurationMs ?? 3e5;
    this.jailThreshold = config?.jailThreshold ?? this.max * 2;
    this.store = config?.store ?? new MemoryStore();
    this.keyGenerator = config?.keyGenerator;
  }
  generateKey(req) {
    if (this.keyGenerator) {
      return this.keyGenerator(req);
    }
    const urlPath = req.url.split("?")[0];
    return `${req.ip}:${urlPath}`;
  }
  async check(req, overrideConfig) {
    const isEnabled = overrideConfig?.enabled ?? this.enabled;
    const windowMs = overrideConfig?.windowMs ?? this.windowMs;
    const max = overrideConfig?.max ?? this.max;
    const jailDuration = overrideConfig?.jailDurationMs ?? this.jailDurationMs;
    const jailThreshold = overrideConfig?.jailThreshold ?? this.jailThreshold;
    const defaultAllowedResult = {
      allowed: true,
      limit: max,
      remaining: max,
      resetTime: Date.now() + windowMs,
      retryAfterSec: 0,
      isJailed: false,
      headers: {}
    };
    if (!isEnabled) {
      return defaultAllowedResult;
    }
    const key = overrideConfig?.keyGenerator ? overrideConfig.keyGenerator(req) : this.generateKey(req);
    const isIpJailed = await this.store.isJailed(req.ip);
    const isKeyJailed = !isIpJailed && await this.store.isJailed(key);
    const jailedKey = isIpJailed ? req.ip : isKeyJailed ? key : null;
    if (jailedKey) {
      const entry = await this.store.get(jailedKey);
      const remainingJailSec = entry?.jailUntil ? Math.max(1, Math.ceil((entry.jailUntil - Date.now()) / 1e3)) : Math.ceil(jailDuration / 1e3);
      return {
        allowed: false,
        limit: max,
        remaining: 0,
        resetTime: entry?.jailUntil || Date.now() + jailDuration,
        retryAfterSec: remainingJailSec,
        isJailed: true,
        headers: {
          "X-RateLimit-Limit": String(max),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(Math.ceil((entry?.jailUntil || Date.now() + jailDuration) / 1e3)),
          "Retry-After": String(remainingJailSec)
        }
      };
    }
    const { count, resetTime } = await this.store.increment(key, windowMs);
    const retryAfterSec = Math.max(1, Math.ceil((resetTime - Date.now()) / 1e3));
    const remaining = Math.max(0, max - count);
    const headers = {
      "X-RateLimit-Limit": String(max),
      "X-RateLimit-Remaining": String(remaining),
      "X-RateLimit-Reset": String(Math.ceil(resetTime / 1e3))
    };
    if (count >= jailThreshold) {
      await this.store.jail(key, jailDuration);
      headers["Retry-After"] = String(Math.ceil(jailDuration / 1e3));
      return {
        allowed: false,
        limit: max,
        remaining: 0,
        resetTime: Date.now() + jailDuration,
        retryAfterSec: Math.ceil(jailDuration / 1e3),
        isJailed: true,
        headers
      };
    }
    if (count > max) {
      headers["Retry-After"] = String(retryAfterSec);
      return {
        allowed: false,
        limit: max,
        remaining: 0,
        resetTime,
        retryAfterSec,
        isJailed: false,
        headers
      };
    }
    return {
      allowed: true,
      limit: max,
      remaining,
      resetTime,
      retryAfterSec: 0,
      isJailed: false,
      headers
    };
  }
  async jailKey(key, durationMs) {
    await this.store.jail(key, durationMs);
  }
  getStore() {
    return this.store;
  }
};

// src/core/ip-filter.ts
function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10) >>> 0, 0) >>> 0;
}
function parseCidr(cidr) {
  const parts = cidr.trim().split("/");
  if (parts.length === 1) {
    const ip = parts[0];
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
    return {
      network: ipv4ToInt(ip),
      mask: 4294967295 >>> 0
    };
  }
  if (parts.length === 2) {
    const ip = parts[0];
    const prefix = parseInt(parts[1], 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
    const mask = prefix === 0 ? 0 : -1 << 32 - prefix >>> 0;
    const network = (ipv4ToInt(ip) & mask) >>> 0;
    return { network, mask };
  }
  return null;
}
function isIpInSubnet(ip, subnet) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  const ipInt = ipv4ToInt(ip);
  return (ipInt & subnet.mask) >>> 0 === subnet.network;
}
var IPFilter = class {
  whitelistSubnets = [];
  blacklistSubnets = [];
  whitelistExact = /* @__PURE__ */ new Set();
  blacklistExact = /* @__PURE__ */ new Set();
  trustProxy;
  customIpHeader;
  constructor(config) {
    this.trustProxy = config?.trustProxy ?? true;
    this.customIpHeader = config?.customIpHeader?.toLowerCase();
    if (config?.whitelist) {
      for (const item of config.whitelist) {
        const cleaned = item.trim();
        const subnet = parseCidr(cleaned);
        if (subnet) {
          this.whitelistSubnets.push(subnet);
        } else {
          this.whitelistExact.add(cleaned.toLowerCase());
        }
      }
    }
    if (config?.blacklist) {
      for (const item of config.blacklist) {
        const cleaned = item.trim();
        const subnet = parseCidr(cleaned);
        if (subnet) {
          this.blacklistSubnets.push(subnet);
        } else {
          this.blacklistExact.add(cleaned.toLowerCase());
        }
      }
    }
  }
  /**
   * Resolves the real client IP from request headers or socket info
   */
  resolveClientIp(headers, socketIp) {
    if (this.customIpHeader) {
      const custom = headers[this.customIpHeader];
      if (custom) {
        const ipStr = Array.isArray(custom) ? custom[0] : custom;
        return ipStr.split(",")[0].trim();
      }
    }
    if (this.trustProxy) {
      const cfIp = headers["cf-connecting-ip"];
      if (cfIp) return (Array.isArray(cfIp) ? cfIp[0] : cfIp).trim();
      const realIp = headers["x-real-ip"];
      if (realIp) return (Array.isArray(realIp) ? realIp[0] : realIp).trim();
      const xForwardedFor = headers["x-forwarded-for"];
      if (xForwardedFor) {
        const forwarded = Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor;
        const first = forwarded.split(",")[0].trim();
        if (first) return first;
      }
    }
    return socketIp || "127.0.0.1";
  }
  isWhitelisted(ip) {
    const cleanIp = ip.trim().toLowerCase();
    if (this.whitelistExact.has(cleanIp)) return true;
    for (const subnet of this.whitelistSubnets) {
      if (isIpInSubnet(cleanIp, subnet)) return true;
    }
    return false;
  }
  isBlacklisted(ip) {
    const cleanIp = ip.trim().toLowerCase();
    if (this.blacklistExact.has(cleanIp)) return true;
    for (const subnet of this.blacklistSubnets) {
      if (isIpInSubnet(cleanIp, subnet)) return true;
    }
    return false;
  }
};

// src/core/honeypot.ts
var DEFAULT_HONEYPOT_PATHS = [
  /^\/\.env(?:\..*)?$/i,
  /^\/\.git(?:\/.*)?$/i,
  /^\/\.aws(?:\/.*)?$/i,
  /^\/\.ssh(?:\/.*)?$/i,
  /^\/wp-admin(?:\/.*)?$/i,
  /^\/wp-login\.php$/i,
  /^\/wp-content(?:\/.*)?$/i,
  /^\/xmlrpc\.php$/i,
  /^\/phpmyadmin(?:\/.*)?$/i,
  /^\/pma(?:\/.*)?$/i,
  /^\/myadmin(?:\/.*)?$/i,
  /^\/actuator(?:\/.*)?$/i,
  /^\/solr(?:\/.*)?$/i,
  /^\/autodiscover\/autodiscover\.xml$/i,
  /^\/web\.config$/i,
  /^\/\.ds_store$/i,
  /^\/id_rsa$/i,
  /^\/backup(?:\.sql|\.tar|\.zip|\.gz)?$/i,
  /^\/dump\.sql$/i
];
var HoneypotTrap = class {
  enabled;
  trapPaths;
  jailDurationMs;
  constructor(config) {
    if (typeof config === "boolean") {
      this.enabled = config;
      this.trapPaths = [...DEFAULT_HONEYPOT_PATHS];
      this.jailDurationMs = 24 * 60 * 60 * 1e3;
    } else {
      this.enabled = config?.enabled ?? true;
      this.trapPaths = config?.trapPaths ?? [...DEFAULT_HONEYPOT_PATHS];
      this.jailDurationMs = config?.jailDurationMs ?? 24 * 60 * 60 * 1e3;
    }
  }
  isTrap(pathname) {
    if (!this.enabled) return false;
    const normalized = pathname.toLowerCase();
    for (const pattern of this.trapPaths) {
      if (pattern instanceof RegExp) {
        if (pattern.test(normalized)) return true;
      } else if (typeof pattern === "string") {
        if (pattern.endsWith("*")) {
          const base = pattern.slice(0, -1).toLowerCase();
          if (normalized.startsWith(base)) return true;
        } else if (pattern.toLowerCase() === normalized) {
          return true;
        }
      }
    }
    return false;
  }
  getJailDuration() {
    return this.jailDurationMs;
  }
};

// src/core/reputation.ts
var THREAT_STRIKE_WEIGHTS = {
  honeypot_triggered: 5,
  command_injection: 5,
  prototype_pollution: 5,
  sql_injection: 3,
  nosql_injection: 3,
  ssrf: 3,
  path_traversal: 3,
  xss: 3,
  bad_bot: 2,
  rate_limit_exceeded: 1,
  payload_too_large: 1,
  suspicious_header: 1,
  custom_rule_violation: 2,
  ip_blacklisted: 5
};
var ReputationEngine = class {
  enabled;
  maxStrikes;
  windowMs;
  baseJailMs;
  records = /* @__PURE__ */ new Map();
  constructor(config) {
    if (typeof config === "boolean") {
      this.enabled = config;
      this.maxStrikes = 5;
      this.windowMs = 60 * 60 * 1e3;
      this.baseJailMs = 15 * 60 * 1e3;
    } else {
      this.enabled = config?.enabled ?? false;
      this.maxStrikes = config?.maxStrikes ?? 5;
      this.windowMs = config?.windowMs ?? 60 * 60 * 1e3;
      this.baseJailMs = config?.jailDurationMs ?? 15 * 60 * 1e3;
    }
  }
  /**
   * Adds strikes for a detected threat.
   * Returns whether the IP should now be jailed and for how many milliseconds.
   */
  addStrike(ip, threat) {
    if (!this.enabled || ip === "127.0.0.1" || ip === "::1") {
      return { shouldJail: false, jailDurationMs: 0, totalStrikes: 0 };
    }
    const now = Date.now();
    let record = this.records.get(ip);
    if (!record || now - record.lastStrikeTime > this.windowMs) {
      record = { strikes: 0, lastStrikeTime: now, jailCount: record ? record.jailCount : 0 };
      this.records.set(ip, record);
    }
    const weight = threat ? THREAT_STRIKE_WEIGHTS[threat] ?? 1 : 1;
    record.strikes += weight;
    record.lastStrikeTime = now;
    if (record.strikes >= this.maxStrikes) {
      record.jailCount++;
      record.strikes = 0;
      let multiplier = 1;
      if (record.jailCount === 2) multiplier = 8;
      else if (record.jailCount === 3) multiplier = 96;
      else if (record.jailCount >= 4) multiplier = 672;
      const jailDurationMs = this.baseJailMs * multiplier;
      return {
        shouldJail: true,
        jailDurationMs,
        totalStrikes: record.strikes
      };
    }
    return {
      shouldJail: false,
      jailDurationMs: 0,
      totalStrikes: record.strikes
    };
  }
  getRecord(ip) {
    return this.records.get(ip);
  }
  clear() {
    this.records.clear();
  }
};

// src/core/tarpit.ts
var DefensiveTarpit = class {
  enabled;
  delayMs;
  applyOnThreats;
  constructor(config) {
    if (typeof config === "boolean") {
      this.enabled = config;
      this.delayMs = 3e3;
      this.applyOnThreats = null;
    } else {
      this.enabled = config?.enabled ?? false;
      this.delayMs = config?.delayMs ?? 3e3;
      this.applyOnThreats = config?.applyOnThreats ? new Set(config.applyOnThreats) : null;
    }
  }
  /**
   * Applies delay if tarpit is enabled for this threat type
   */
  async delay(threat) {
    if (!this.enabled) return;
    if (this.applyOnThreats && threat && !this.applyOnThreats.has(threat)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, this.delayMs));
  }
  isEnabled() {
    return this.enabled;
  }
};

// src/core/engine.ts
function generateRequestId() {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return `ng_${ts}_${rand}`;
}
function matchPath(pattern, path) {
  if (pattern instanceof RegExp) {
    return pattern.test(path);
  }
  if (pattern.endsWith("*")) {
    const base = pattern.slice(0, -1);
    return path.startsWith(base);
  }
  return pattern === path;
}
var NextGuardEngine = class {
  config;
  sqliDetector;
  nosqliDetector;
  protoDetector;
  ssrfDetector;
  xssDetector;
  cmdDetector;
  pathDetector;
  botDetector;
  rateLimiter;
  ipFilter;
  honeypot;
  reputation;
  tarpit;
  constructor(config = {}) {
    this.config = config;
    const sqliCfg = typeof config.sqlInjection === "object" ? config.sqlInjection : {};
    this.sqliDetector = new SQLInjectionDetector(sqliCfg);
    const nosqliCfg = typeof config.nosqlInjection === "object" ? config.nosqlInjection : {};
    this.nosqliDetector = new NoSQLInjectionDetector(nosqliCfg);
    const protoCfg = typeof config.prototypePollution === "object" ? config.prototypePollution : {};
    this.protoDetector = new PrototypePollutionDetector(protoCfg);
    const ssrfCfg = typeof config.ssrf === "object" ? config.ssrf : {};
    this.ssrfDetector = new SSRFDetector(ssrfCfg);
    const xssCfg = typeof config.xss === "object" ? config.xss : {};
    this.xssDetector = new XSSDetector(xssCfg);
    const cmdCfg = typeof config.commandInjection === "object" ? config.commandInjection : {};
    this.cmdDetector = new CommandInjectionDetector(cmdCfg);
    const pathCfg = typeof config.pathTraversal === "object" ? config.pathTraversal : {};
    this.pathDetector = new PathTraversalDetector(pathCfg);
    const botCfg = typeof config.badBots === "object" ? config.badBots : {};
    this.botDetector = new BotDetector(botCfg);
    const rlCfg = typeof config.rateLimit === "object" ? config.rateLimit : void 0;
    this.rateLimiter = new RateLimiter(rlCfg);
    this.ipFilter = new IPFilter(config.ipFilter);
    this.honeypot = new HoneypotTrap(config.honeypot);
    this.reputation = new ReputationEngine(config.reputation);
    this.tarpit = new DefensiveTarpit(config.tarpit);
  }
  /**
   * Find matching endpoint override if defined in config.endpoints
   */
  getEndpointOverride(urlPath) {
    if (!this.config.endpoints) return null;
    for (const [pattern, override] of Object.entries(this.config.endpoints)) {
      if (matchPath(pattern, urlPath)) {
        return override;
      }
    }
    return null;
  }
  /**
   * Main inspection method that verifies every incoming request against all firewall rules
   */
  async inspect(req) {
    const requestId = generateRequestId();
    const timestamp = Date.now();
    const mode = this.config.mode || "enforce";
    const clientIp = this.ipFilter.resolveClientIp(req.headers, req.ip);
    const urlObj = req.url.startsWith("http") ? new URL(req.url) : new URL(`http://localhost${req.url}`);
    const pathname = urlObj.pathname;
    if (this.config.excludePaths) {
      for (const pattern of this.config.excludePaths) {
        if (matchPath(pattern, pathname)) {
          return {
            allowed: true,
            statusCode: 200,
            clientIp,
            requestId,
            timestamp,
            mode
          };
        }
      }
    }
    if (this.ipFilter.isWhitelisted(clientIp)) {
      return {
        allowed: true,
        statusCode: 200,
        clientIp,
        requestId,
        timestamp,
        mode
      };
    }
    if (this.ipFilter.isBlacklisted(clientIp)) {
      const verdict2 = {
        allowed: mode === "monitor",
        threatType: "ip_blacklisted",
        reason: `IP address ${clientIp} is explicitly blacklisted`,
        statusCode: 403,
        clientIp,
        requestId,
        location: "ip",
        timestamp,
        mode
      };
      await this.handleVerdict(verdict2, req);
      return verdict2;
    }
    const override = this.getEndpointOverride(pathname);
    const honeypotConfig = override?.honeypot !== void 0 ? override.honeypot : this.config.honeypot;
    if (honeypotConfig !== false && this.honeypot.isTrap(pathname)) {
      const jailDuration = this.honeypot.getJailDuration();
      await this.rateLimiter.jailKey(clientIp, jailDuration);
      const verdict2 = {
        allowed: mode === "monitor",
        threatType: "honeypot_triggered",
        reason: `Honeypot trap triggered: ${pathname}. Scanner IP automatically jailed.`,
        statusCode: 403,
        clientIp,
        requestId,
        location: "url",
        timestamp,
        mode
      };
      await this.handleVerdict(verdict2, req);
      return verdict2;
    }
    const botConfig = override?.badBots !== void 0 ? override.badBots : this.config.badBots;
    if (botConfig !== false) {
      const userAgentHeader = req.headers["user-agent"];
      const userAgent = Array.isArray(userAgentHeader) ? userAgentHeader[0] : userAgentHeader;
      const botResult = this.botDetector.detectUserAgent(userAgent);
      if (botResult.detected) {
        const verdict2 = {
          allowed: mode === "monitor",
          threatType: "bad_bot",
          reason: botResult.reason || "Malicious bot or scanner detected",
          statusCode: 403,
          clientIp,
          requestId,
          location: "header",
          parameter: "user-agent",
          timestamp,
          mode
        };
        await this.handleVerdict(verdict2, req);
        return verdict2;
      }
    }
    const rateLimitConfig = override?.rateLimit !== void 0 ? override.rateLimit : this.config.rateLimit;
    if (rateLimitConfig !== false) {
      const rlResult = await this.rateLimiter.check(
        { ...req, ip: clientIp },
        typeof rateLimitConfig === "object" ? rateLimitConfig : void 0
      );
      if (!rlResult.allowed) {
        const verdict2 = {
          allowed: mode === "monitor",
          threatType: "rate_limit_exceeded",
          reason: rlResult.isJailed ? `Too many suspicious requests. IP temporarily jailed for ${rlResult.retryAfterSec} seconds.` : `Rate limit of ${rlResult.limit} requests exceeded. Try again in ${rlResult.retryAfterSec} seconds.`,
          statusCode: 429,
          clientIp,
          requestId,
          timestamp,
          mode
        };
        await this.handleVerdict(verdict2, req);
        return verdict2;
      }
    }
    const payloadCfg = override?.payloadGuard !== void 0 ? override.payloadGuard : this.config.payloadGuard;
    if (payloadCfg !== false) {
      const maxSize = typeof payloadCfg === "object" && payloadCfg.maxBodySize ? payloadCfg.maxBodySize : 10 * 1024 * 1024;
      const contentLength = req.headers["content-length"];
      if (contentLength) {
        const len = parseInt(Array.isArray(contentLength) ? contentLength[0] : contentLength, 10);
        if (!isNaN(len) && len > maxSize) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "payload_too_large",
            reason: `Payload size (${len} bytes) exceeds limit of ${maxSize} bytes`,
            statusCode: 413,
            clientIp,
            requestId,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const pathConfig = override?.pathTraversal !== void 0 ? override.pathTraversal : this.config.pathTraversal;
    if (pathConfig !== false) {
      const pathResult = this.pathDetector.detectValue(pathname, "url_path");
      if (pathResult.detected) {
        const verdict2 = {
          allowed: mode === "monitor",
          threatType: "path_traversal",
          reason: "Path traversal attempt detected in URL",
          matchedPattern: pathResult.pattern,
          statusCode: 403,
          clientIp,
          requestId,
          location: "url",
          timestamp,
          mode
        };
        await this.handleVerdict(verdict2, req);
        return verdict2;
      }
      if (req.query) {
        const qResult = this.pathDetector.detectObject(req.query, "query");
        if (qResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "path_traversal",
            reason: `Path traversal attempt detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "query",
            parameter: qResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const sqliConfig = override?.sqlInjection !== void 0 ? override.sqlInjection : this.config.sqlInjection;
    if (sqliConfig !== false) {
      if (req.query) {
        const qResult = this.sqliDetector.detectObject(req.query, "query");
        if (qResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "sql_injection",
            reason: `SQL Injection detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "query",
            parameter: qResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
      if (req.body) {
        const bResult = this.sqliDetector.detectObject(req.body, "body");
        if (bResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "sql_injection",
            reason: `SQL Injection detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "body",
            parameter: bResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
      if (req.rawBody && typeof req.rawBody === "string") {
        const rbResult = this.sqliDetector.detectValue(req.rawBody, "rawBody");
        if (rbResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "sql_injection",
            reason: "SQL Injection detected in request payload",
            matchedPattern: rbResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "body",
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const nosqliConfig = override?.nosqlInjection !== void 0 ? override.nosqlInjection : this.config.nosqlInjection;
    if (nosqliConfig !== false) {
      if (req.query) {
        const qResult = this.nosqliDetector.detectObject(req.query, "query");
        if (qResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "nosql_injection",
            reason: `NoSQL Injection detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "query",
            parameter: qResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
      if (req.body) {
        const bResult = this.nosqliDetector.detectObject(req.body, "body");
        if (bResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "nosql_injection",
            reason: `NoSQL Injection detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "body",
            parameter: bResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const protoConfig = override?.prototypePollution !== void 0 ? override.prototypePollution : this.config.prototypePollution;
    if (protoConfig !== false) {
      if (req.query) {
        const qResult = this.protoDetector.detectObject(req.query, "query");
        if (qResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "prototype_pollution",
            reason: `Prototype pollution attempt detected in parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "query",
            parameter: qResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
      if (req.body) {
        const bResult = this.protoDetector.detectObject(req.body, "body");
        if (bResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "prototype_pollution",
            reason: `Prototype pollution attempt detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "body",
            parameter: bResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const ssrfConfig = override?.ssrf !== void 0 ? override.ssrf : this.config.ssrf;
    if (ssrfConfig !== false && ssrfConfig !== void 0) {
      if (req.query) {
        const qResult = this.ssrfDetector.detectObject(req.query, "query");
        if (qResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "ssrf",
            reason: `SSRF target address detected in query parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "query",
            parameter: qResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const xssConfig = override?.xss !== void 0 ? override.xss : this.config.xss;
    if (xssConfig !== false) {
      if (req.query) {
        const qResult = this.xssDetector.detectObject(req.query, "query");
        if (qResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "xss",
            reason: `XSS attack payload detected in query parameter: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "query",
            parameter: qResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
      if (req.body) {
        const bResult = this.xssDetector.detectObject(req.body, "body");
        if (bResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "xss",
            reason: `XSS attack payload detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "body",
            parameter: bResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const cmdConfig = override?.commandInjection !== void 0 ? override.commandInjection : this.config.commandInjection;
    if (cmdConfig !== false) {
      if (req.query) {
        const qResult = this.cmdDetector.detectObject(req.query, "query");
        if (qResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "command_injection",
            reason: `OS Command Injection signature detected in query: ${qResult.parameter}`,
            matchedPattern: qResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "query",
            parameter: qResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
      if (req.body) {
        const bResult = this.cmdDetector.detectObject(req.body, "body");
        if (bResult.detected) {
          const verdict2 = {
            allowed: mode === "monitor",
            threatType: "command_injection",
            reason: `OS Command Injection signature detected in body: ${bResult.parameter}`,
            matchedPattern: bResult.pattern,
            statusCode: 403,
            clientIp,
            requestId,
            location: "body",
            parameter: bResult.parameter,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    if (this.config.customRules && this.config.customRules.length > 0) {
      for (const rule of this.config.customRules) {
        const triggered = await rule.evaluate(req);
        if (triggered) {
          const action = rule.action || "block";
          const verdict2 = {
            allowed: action === "monitor" || mode === "monitor",
            threatType: "custom_rule_violation",
            reason: rule.reason || `Custom rule violated: ${rule.name}`,
            statusCode: rule.statusCode || 403,
            clientIp,
            requestId,
            timestamp,
            mode
          };
          await this.handleVerdict(verdict2, req);
          return verdict2;
        }
      }
    }
    const verdict = {
      allowed: true,
      statusCode: 200,
      clientIp,
      requestId,
      timestamp,
      mode
    };
    if (this.config.onAllowed) {
      try {
        await this.config.onAllowed(verdict, req);
      } catch (err) {
        console.error("[NextGuard] Error in onAllowed hook:", err);
      }
    }
    return verdict;
  }
  async handleVerdict(verdict, req) {
    if (!verdict.allowed || verdict.mode === "monitor") {
      if (verdict.clientIp && verdict.threatType) {
        const { shouldJail, jailDurationMs } = this.reputation.addStrike(verdict.clientIp, verdict.threatType);
        if (shouldJail) {
          await this.rateLimiter.jailKey(verdict.clientIp, jailDurationMs);
        }
      }
      await this.tarpit.delay(verdict.threatType);
      if (this.config.onBlocked) {
        try {
          await this.config.onBlocked(verdict, req);
        } catch (err) {
          console.error("[NextGuard] Error in onBlocked hook:", err);
        }
      }
    }
  }
  getRateLimiter() {
    return this.rateLimiter;
  }
  getIPFilter() {
    return this.ipFilter;
  }
  getReputation() {
    return this.reputation;
  }
  getHoneypot() {
    return this.honeypot;
  }
  getTarpit() {
    return this.tarpit;
  }
};

// src/security/headers.ts
function getSecurityHeaders(config) {
  if (config === false) return {};
  const cfg = typeof config === "object" ? config : {};
  if (cfg.enabled === false) return {};
  const headers = {};
  if (cfg.xContentTypeOptions !== false) {
    headers["X-Content-Type-Options"] = "nosniff";
  }
  if (cfg.xFrameOptions !== false) {
    headers["X-Frame-Options"] = cfg.xFrameOptions || "DENY";
  }
  if (cfg.xXSSProtection !== false) {
    headers["X-XSS-Protection"] = cfg.xXSSProtection || "0";
  }
  if (cfg.referrerPolicy !== false) {
    headers["Referrer-Policy"] = cfg.referrerPolicy || "strict-origin-when-cross-origin";
  }
  if (cfg.strictTransportSecurity !== false) {
    headers["Strict-Transport-Security"] = typeof cfg.strictTransportSecurity === "string" ? cfg.strictTransportSecurity : "max-age=31536000; includeSubDomains; preload";
  }
  if (cfg.permissionsPolicy !== false) {
    headers["Permissions-Policy"] = typeof cfg.permissionsPolicy === "string" ? cfg.permissionsPolicy : "camera=(), microphone=(), geolocation=(), interest-cohort=()";
  }
  if (cfg.contentSecurityPolicy) {
    headers["Content-Security-Policy"] = cfg.contentSecurityPolicy;
  }
  return headers;
}

// src/templates/blocked-page.ts
function renderBlockedJson(verdict) {
  return {
    success: false,
    error: "Access Denied by NextGuard Firewall",
    code: "FIREWALL_BLOCKED",
    threat: verdict.threatType,
    reason: verdict.reason,
    clientIp: verdict.clientIp,
    requestId: verdict.requestId,
    timestamp: new Date(verdict.timestamp).toISOString()
  };
}
function renderBlockedHtml(verdict) {
  const threatTitle = formatThreatTitle(verdict.threatType);
  const dateFormatted = new Date(verdict.timestamp).toUTCString();
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 Forbidden - NextGuard Security</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #0b0f19;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: #151c2c;
      border: 1px solid #2d3748;
      border-radius: 12px;
      max-width: 600px;
      width: 100%;
      padding: 2.5rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
    }
    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 1.5rem;
    }
    .shield-icon {
      width: 44px;
      height: 44px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ef4444;
      font-weight: bold;
      font-size: 20px;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: #ffffff;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      background: #3b82f6;
      color: #ffffff;
      margin-top: 4px;
    }
    .message {
      font-size: 1rem;
      color: #94a3b8;
      line-height: 1.6;
      margin-bottom: 2rem;
    }
    .meta-box {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1.5rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
    }
    .meta-row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      border-bottom: 1px solid #1e293b;
    }
    .meta-row:last-child {
      border-bottom: none;
    }
    .meta-label {
      color: #64748b;
    }
    .meta-value {
      color: #cbd5e1;
      font-weight: 500;
    }
    .footer {
      text-align: center;
      font-size: 0.75rem;
      color: #475569;
      border-top: 1px solid #1e293b;
      padding-top: 1.25rem;
    }
    .footer a {
      color: #3b82f6;
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="shield-icon">\u{1F6E1}\uFE0F</div>
      <div>
        <h1>Security Block</h1>
        <span class="badge">NextGuard WAF</span>
      </div>
    </div>
    <p class="message">
      Access to this resource was blocked due to suspicious activity violating security policies (<strong>${escapeHtml(threatTitle)}</strong>).
    </p>
    <div class="meta-box">
      <div class="meta-row">
        <span class="meta-label">Reason:</span>
        <span class="meta-value">${escapeHtml(verdict.reason || "Security threat detected")}</span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Client IP:</span>
        <span class="meta-value">${escapeHtml(verdict.clientIp)}</span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Request ID:</span>
        <span class="meta-value">${escapeHtml(verdict.requestId)}</span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Timestamp:</span>
        <span class="meta-value">${escapeHtml(dateFormatted)}</span>
      </div>
    </div>
    <div class="footer">
      Protected by <strong>NextGuard Firewall</strong> &bull; If you believe this is a mistake, contact site administration with your Request ID.
    </div>
  </div>
</body>
</html>`;
}
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
function formatThreatTitle(threat) {
  switch (threat) {
    case "sql_injection":
      return "SQL Injection Detected";
    case "nosql_injection":
      return "NoSQL Injection Detected";
    case "prototype_pollution":
      return "Prototype Pollution Detected";
    case "ssrf":
      return "Server-Side Request Forgery (SSRF) Detected";
    case "honeypot_triggered":
      return "Security Tripwire / Honeypot Triggered";
    case "xss":
      return "Cross-Site Scripting (XSS) Detected";
    case "command_injection":
      return "Command Injection Detected";
    case "path_traversal":
      return "Path Traversal Detected";
    case "rate_limit_exceeded":
      return "Rate Limit / DoS Protection Triggered";
    case "bad_bot":
      return "Automated Scanner or Malicious Bot Detected";
    case "ip_blacklisted":
      return "IP Address Blacklisted";
    case "payload_too_large":
      return "Payload Size Limit Exceeded";
    default:
      return "Suspicious Request Blocked";
  }
}

// src/middleware/nextjs.ts
async function extractRequestContext(req, inspectBody = false) {
  const url = req.url;
  const method = req.method;
  const headers = {};
  req.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  const query = {};
  try {
    const urlObj = new URL(url);
    urlObj.searchParams.forEach((val, k) => {
      query[k] = val;
    });
  } catch {
  }
  const ip = ("ip" in req && typeof req.ip === "string" ? req.ip : void 0) || headers["cf-connecting-ip"] || headers["x-real-ip"] || (headers["x-forwarded-for"] ? headers["x-forwarded-for"].split(",")[0].trim() : "127.0.0.1");
  let body = void 0;
  let rawBody = void 0;
  if (inspectBody && ["POST", "PUT", "PATCH", "DELETE"].includes(method.toUpperCase())) {
    try {
      const clonedReq = typeof req.clone === "function" ? req.clone() : req;
      const contentType = headers["content-type"] || "";
      if (contentType.includes("application/json") && typeof clonedReq.json === "function") {
        body = await clonedReq.json();
      } else if (typeof clonedReq.text === "function") {
        rawBody = await clonedReq.text();
        try {
          body = JSON.parse(rawBody);
        } catch {
        }
      }
    } catch {
    }
  }
  return {
    url,
    method,
    ip,
    headers,
    query,
    body,
    rawBody
  };
}
function createBlockedResponse(verdict, headers = {}, preferHtml = false) {
  const securityHeaders = getSecurityHeaders();
  const mergedHeaders = new Headers({
    ...securityHeaders,
    ...headers
  });
  if (preferHtml) {
    mergedHeaders.set("Content-Type", "text/html; charset=utf-8");
    return new Response(renderBlockedHtml(verdict), {
      status: verdict.statusCode,
      headers: mergedHeaders
    });
  }
  mergedHeaders.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(renderBlockedJson(verdict)), {
    status: verdict.statusCode,
    headers: mergedHeaders
  });
}
function createNextGuardMiddleware(config = {}) {
  const engine = new NextGuardEngine(config);
  getSecurityHeaders(config.securityHeaders);
  return async function nextGuardMiddleware(req) {
    const ctx = await extractRequestContext(req, false);
    const verdict = await engine.inspect(ctx);
    if (!verdict.allowed) {
      const acceptHeader = req.headers.get("accept") || "";
      const isHtml = config.htmlResponse !== false && acceptHeader.includes("text/html");
      return createBlockedResponse(verdict, {}, isHtml);
    }
    return void 0;
  };
}
function withNextGuard(handler, endpointConfig = {}) {
  const engine = new NextGuardEngine(endpointConfig);
  const secHeaders = getSecurityHeaders(endpointConfig.securityHeaders);
  return async function wrappedRouteHandler(req, context) {
    const ctx = await extractRequestContext(req, true);
    const verdict = await engine.inspect(ctx);
    if (!verdict.allowed) {
      const accept = req.headers.get("accept") || "";
      const isHtml = endpointConfig.htmlResponse && accept.includes("text/html");
      return createBlockedResponse(verdict, {}, isHtml);
    }
    const response = await handler(req, context);
    for (const [key, value] of Object.entries(secHeaders)) {
      if (!response.headers.has(key)) {
        response.headers.set(key, value);
      }
    }
    return response;
  };
}
function withNextGuardPages(handler, endpointConfig = {}) {
  const engine = new NextGuardEngine(endpointConfig);
  const secHeaders = getSecurityHeaders(endpointConfig.securityHeaders);
  return async function wrappedPagesHandler(req, res) {
    const headers = {};
    for (const [key, value] of Object.entries(req.headers || {})) {
      headers[key.toLowerCase()] = Array.isArray(value) ? value[0] : value;
    }
    const ip = req.headers["cf-connecting-ip"] || req.headers["x-real-ip"] || (req.headers["x-forwarded-for"] ? req.headers["x-forwarded-for"].split(",")[0].trim() : req.socket?.remoteAddress || "127.0.0.1");
    const ctx = {
      url: req.url || "/",
      method: req.method || "GET",
      ip,
      headers,
      query: req.query,
      body: req.body
    };
    const verdict = await engine.inspect(ctx);
    if (!verdict.allowed) {
      const accept = headers["accept"] || "";
      const isHtml = endpointConfig.htmlResponse && accept.includes("text/html");
      for (const [k, v] of Object.entries(secHeaders)) {
        res.setHeader(k, v);
      }
      if (isHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.status(verdict.statusCode).send(renderBlockedHtml(verdict));
        return;
      }
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.status(verdict.statusCode).json(renderBlockedJson(verdict));
      return;
    }
    for (const [k, v] of Object.entries(secHeaders)) {
      res.setHeader(k, v);
    }
    return handler(req, res);
  };
}

// src/middleware/express.ts
function nextGuardExpress(config = {}) {
  const engine = new NextGuardEngine(config);
  const secHeaders = getSecurityHeaders(config.securityHeaders);
  return async function nextGuardMiddleware(req, res, next) {
    try {
      const headers = {};
      for (const [key, value] of Object.entries(req.headers || {})) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value[0] : value;
      }
      const ip = headers["cf-connecting-ip"] || headers["x-real-ip"] || (headers["x-forwarded-for"] ? headers["x-forwarded-for"].split(",")[0].trim() : req.ip || req.socket?.remoteAddress || "127.0.0.1");
      const ctx = {
        url: req.originalUrl || req.url || "/",
        method: req.method || "GET",
        ip,
        headers,
        query: req.query,
        body: req.body
      };
      const verdict = await engine.inspect(ctx);
      for (const [headerName, headerValue] of Object.entries(secHeaders)) {
        res.setHeader(headerName, headerValue);
      }
      if (!verdict.allowed) {
        const accept = headers["accept"] || "";
        const isHtml = config.htmlResponse && accept.includes("text/html");
        if (isHtml) {
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          res.status(verdict.statusCode).send(renderBlockedHtml(verdict));
          return;
        }
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.status(verdict.statusCode).json(renderBlockedJson(verdict));
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

// src/core/stores/redis-store.ts
var RedisStore = class {
  client;
  prefix;
  constructor(options) {
    this.client = options.client;
    this.prefix = options.prefix || "nextguard:rl:";
  }
  getKey(key) {
    return `${this.prefix}${key}`;
  }
  getJailKey(key) {
    return `${this.prefix}jail:${key}`;
  }
  async increment(key, windowMs) {
    const redisKey = this.getKey(key);
    const count = await this.client.incr(redisKey);
    if (count === 1) {
      const ttlSec = Math.ceil(windowMs / 1e3);
      await this.client.expire(redisKey, ttlSec);
      return { count: 1, resetTime: Date.now() + windowMs };
    }
    const ttl = await this.client.ttl(redisKey);
    const resetTime = ttl > 0 ? Date.now() + ttl * 1e3 : Date.now() + windowMs;
    return { count, resetTime };
  }
  async get(key) {
    const redisKey = this.getKey(key);
    const jailKey = this.getJailKey(key);
    const [val, ttl, jailVal] = await Promise.all([
      this.client.get(redisKey),
      this.client.ttl(redisKey),
      this.client.get(jailKey)
    ]);
    if (!val && !jailVal) return null;
    const count = val ? parseInt(val, 10) : 0;
    const resetTime = ttl > 0 ? Date.now() + ttl * 1e3 : Date.now();
    const isJailed = jailVal !== null;
    return {
      count,
      resetTime,
      isJailed,
      jailUntil: isJailed ? resetTime : 0
    };
  }
  async jail(key, durationMs) {
    const jailKey = this.getJailKey(key);
    const ttlSec = Math.ceil(durationMs / 1e3);
    await this.client.set(jailKey, "1", "EX", ttlSec);
  }
  async isJailed(key) {
    const jailKey = this.getJailKey(key);
    const val = await this.client.get(jailKey);
    return val !== null;
  }
  async reset(key) {
    await Promise.all([
      this.client.del(this.getKey(key)),
      this.client.del(this.getJailKey(key))
    ]);
  }
};

// src/registry.ts
function normalizePath(rawUrl) {
  try {
    const urlObj = rawUrl.startsWith("http") ? new URL(rawUrl) : new URL(`http://localhost${rawUrl}`);
    let pathname = urlObj.pathname;
    if (pathname.length > 1 && pathname.endsWith("/")) {
      pathname = pathname.slice(0, -1);
    }
    return pathname.toLowerCase();
  } catch {
    return rawUrl.split("?")[0].split("#")[0].toLowerCase() || "/";
  }
}
function makeEndpointId(method, rawUrl) {
  return `${method.toUpperCase()}:${normalizePath(rawUrl)}`;
}
var MAX_UNIQUE_IPS = 50;
var EndpointRegistry = class {
  records = /* @__PURE__ */ new Map();
  /**
   * Catat request yang masuk.
   * Jika endpoint belum ada → buat baru.
   * Jika sudah ada → update counter saja (tidak duplikat).
   *
   * @param method HTTP method
   * @param rawUrl URL/path dari request (boleh query string, akan dinormalisasi)
   * @param ip Client IP
   * @param allowed Apakah request diizinkan melewati firewall
   * @param statusCode Status code yang dikirim
   * @returns EndpointRecord yang sudah diperbarui
   */
  record(method, rawUrl, ip, allowed, statusCode) {
    const path = normalizePath(rawUrl);
    const id = `${method.toUpperCase()}:${path}`;
    const now = Date.now();
    let rec = this.records.get(id);
    if (!rec) {
      rec = {
        id,
        method: method.toUpperCase(),
        path,
        firstSeen: now,
        lastSeen: now,
        requestCount: 0,
        blockedCount: 0,
        allowedCount: 0,
        lastStatusCode: statusCode,
        uniqueIps: /* @__PURE__ */ new Set()
      };
      this.records.set(id, rec);
    }
    rec.lastSeen = now;
    rec.requestCount++;
    rec.lastStatusCode = statusCode;
    if (allowed) {
      rec.allowedCount++;
    } else {
      rec.blockedCount++;
    }
    if (rec.uniqueIps.size < MAX_UNIQUE_IPS) {
      rec.uniqueIps.add(ip);
    }
    return rec;
  }
  /**
   * Ambil satu record berdasarkan id ("METHOD:path")
   */
  get(id) {
    return this.records.get(id);
  }
  /**
   * Ambil semua endpoint yang sudah ditemukan
   */
  getAll() {
    return Array.from(this.records.values());
  }
  /**
   * Statistik ringkasan seluruh registry
   */
  getStats() {
    const endpoints = this.getAll();
    return {
      totalEndpoints: endpoints.length,
      totalRequests: endpoints.reduce((s, e) => s + e.requestCount, 0),
      totalBlocked: endpoints.reduce((s, e) => s + e.blockedCount, 0),
      totalAllowed: endpoints.reduce((s, e) => s + e.allowedCount, 0),
      endpoints: endpoints.map(({ uniqueIps, ...rest }) => ({
        ...rest,
        uniqueIpCount: uniqueIps.size
      }))
    };
  }
  /**
   * Hapus semua data (berguna untuk testing)
   */
  clear() {
    this.records.clear();
  }
  /**
   * Jumlah endpoint unik yang sudah diketahui
   */
  get size() {
    return this.records.size;
  }
};

// src/define.ts
function defineEndpointSecurity(config) {
  return Object.freeze({ ...config });
}
function mergeGuard(...configs) {
  const result = {};
  for (const config of configs) {
    for (const [key, value] of Object.entries(config)) {
      if (key.startsWith("$")) continue;
      const existing = result[key];
      if (value === false) {
        result[key] = false;
      } else if (value === void 0) {
        continue;
      } else if (typeof value === "object" && value !== null && !Array.isArray(value) && typeof existing === "object" && existing !== null && !Array.isArray(existing)) {
        result[key] = { ...existing, ...value };
      } else if (Array.isArray(value) && Array.isArray(existing)) {
        result[key] = [...existing, ...value];
      } else {
        result[key] = value;
      }
    }
  }
  const names = [];
  const tags = [];
  let description = "";
  for (const config of configs) {
    if (config.$name) names.push(config.$name);
    if (config.$description) description = config.$description;
    if (config.$tags) tags.push(...config.$tags);
  }
  if (names.length > 0) result.$name = names.join("+");
  if (description) result.$description = description;
  if (tags.length > 0) result.$tags = [...new Set(tags)];
  return Object.freeze(result);
}
function createGuardGroup(base) {
  return {
    base: Object.freeze({ ...base }),
    extend(overrides) {
      return mergeGuard(base, overrides);
    },
    merge(...others) {
      return mergeGuard(base, ...others);
    }
  };
}
function applyGuard(platform, config) {
  switch (platform) {
    case "next-middleware":
      return createNextGuardMiddleware(config);
    case "next-app":
      return (handler) => withNextGuard(handler, config);
    case "next-pages":
      return (handler) => withNextGuardPages(handler, config);
    case "express":
    case "node":
      return nextGuardExpress(config);
    default:
      throw new Error(`[NextGuard] Unknown platform: "${platform}". Use: 'next-middleware' | 'next-app' | 'next-pages' | 'express'`);
  }
}
function withGuard(handler, ...configs) {
  const merged = configs.length === 1 ? configs[0] : mergeGuard(...configs);
  return withNextGuard(handler, merged);
}
function guardExpress(...configs) {
  const merged = configs.length === 1 ? configs[0] : mergeGuard(...configs);
  return nextGuardExpress(merged);
}

// src/presets.ts
var LOGIN = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    // 1 menit
    max: 5,
    // Maksimal 5 percobaan login per menit
    jailThreshold: 10,
    // Banned setelah 10 request
    jailDurationMs: 15 * 60 * 1e3
    // Banned 15 menit
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true, inspectQuery: true },
  xss: { enabled: true, sensitivity: "high" },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true },
  payloadGuard: { enabled: true, maxBodySize: 10 * 1024 }
  // 10 KB saja untuk login
};
var REGISTER = {
  mode: "enforce",
  rateLimit: {
    windowMs: 10 * 60 * 1e3,
    // 10 menit
    max: 3,
    // Hanya 3 pendaftaran per 10 menit per IP
    jailThreshold: 6,
    jailDurationMs: 30 * 60 * 1e3
    // Banned 30 menit
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true },
  payloadGuard: { enabled: true, maxBodySize: 50 * 1024 }
  // 50 KB
};
var FORGOT_PASSWORD = {
  mode: "enforce",
  rateLimit: {
    windowMs: 5 * 60 * 1e3,
    // 5 menit
    max: 3,
    // Maksimal 3 request reset per 5 menit
    jailThreshold: 6,
    jailDurationMs: 30 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true, inspectQuery: true },
  xss: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true }
};
var LOGOUT = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 20 },
  badBots: { enabled: true }
};
var VERIFY_OTP = {
  mode: "enforce",
  rateLimit: {
    windowMs: 5 * 60 * 1e3,
    max: 5,
    // 5 percobaan OTP per 5 menit
    jailThreshold: 10,
    jailDurationMs: 30 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true }
};
var PROFILE = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 30 },
  sqlInjection: { enabled: true, sensitivity: "medium", inspectBody: true, inspectQuery: true },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 5 * 1024 * 1024 }
  // 5 MB
};
var CHANGE_PASSWORD = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 5,
    jailDurationMs: 15 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true }
};
var FILE_UPLOAD = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 20 },
  sqlInjection: { enabled: true, inspectBody: false },
  // body adalah binary, skip body check
  xss: { enabled: false },
  // binary payload, skip
  pathTraversal: { enabled: true, inspectQuery: true },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 50 * 1024 * 1024 }
  // 50 MB
};
var COMMENT = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 10 },
  sqlInjection: { enabled: true, sensitivity: "medium", inspectBody: true },
  xss: { enabled: true, sensitivity: "high" },
  // XSS tinggi krn konten bisa di-render
  commandInjection: { enabled: true },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 10 * 1024 }
  // 10 KB per comment
};
var MESSAGE = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 60 },
  // 60 pesan per menit
  sqlInjection: { enabled: true, inspectBody: true },
  xss: { enabled: true, sensitivity: "high" },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 1 * 1024 * 1024 }
  // 1 MB
};
var SEARCH = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 100 },
  sqlInjection: { enabled: true, sensitivity: "high", inspectQuery: true, inspectBody: false },
  xss: { enabled: true, inspectQuery: true },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true, inspectQuery: true },
  badBots: { enabled: true, knownScanners: true }
};
var PRODUCTS = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 200 },
  sqlInjection: { enabled: true, sensitivity: "medium", inspectQuery: true },
  xss: { enabled: true, inspectQuery: true },
  badBots: { enabled: true, knownScanners: true }
};
var PRODUCT_DETAIL = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 300 },
  sqlInjection: { enabled: true, sensitivity: "medium", inspectQuery: true },
  xss: { enabled: false },
  pathTraversal: { enabled: true },
  badBots: { enabled: true, knownScanners: true }
};
var CREATE_UPDATE = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 30 },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true, inspectQuery: true },
  xss: { enabled: true, sensitivity: "high" },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 5 * 1024 * 1024 }
  // 5 MB
};
var DELETE_DATA = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 20 },
  sqlInjection: { enabled: true, sensitivity: "high", inspectQuery: true, inspectBody: true },
  xss: { enabled: false },
  // delete requests biasanya tidak ada rich content
  badBots: { enabled: true }
};
var BULK = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 10,
    // Bulk ops sangat dibatasi
    jailThreshold: 20,
    jailDurationMs: 10 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 10 * 1024 * 1024 }
  // 10 MB untuk batch
};
var PAYMENT = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 5,
    // Hanya 5 transaksi per menit
    jailThreshold: 8,
    jailDurationMs: 30 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true, inspectQuery: true },
  xss: { enabled: true, sensitivity: "high" },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true, knownScanners: true },
  payloadGuard: { enabled: true, maxBodySize: 50 * 1024 }
  // 50 KB
};
var PAYMENT_WEBHOOK = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 100 },
  // Webhook bisa banyak
  sqlInjection: { enabled: false },
  // payload dari gateway terpercaya
  xss: { enabled: false },
  ipFilter: {
    // Whitelist IP gateway pembayaran (contoh Midtrans & Stripe)
    whitelist: [
      "202.152.0.0/16",
      // Midtrans Indonesia
      "3.18.0.0/16",
      // Stripe AWS US-East
      "54.187.0.0/16"
      // Stripe AWS US-West
    ],
    trustProxy: true
  },
  payloadGuard: { enabled: true, maxBodySize: 1 * 1024 * 1024 }
};
var WITHDRAW = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 3,
    jailThreshold: 5,
    jailDurationMs: 60 * 60 * 1e3
    // Banned 1 jam jika mencurigakan
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true },
  payloadGuard: { enabled: true, maxBodySize: 10 * 1024 }
};
var ADMIN = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 30 },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true, inspectQuery: true },
  xss: { enabled: true, sensitivity: "high" },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true, knownScanners: true },
  // Tambahkan ipFilter.whitelist dengan IP server/office kamu
  ipFilter: {
    whitelist: ["127.0.0.1", "::1"],
    // Ganti dengan IP kantor/server kamu
    trustProxy: true
  }
};
var ADMIN_LOGIN = {
  mode: "enforce",
  rateLimit: {
    windowMs: 5 * 60 * 1e3,
    // 5 menit
    max: 3,
    // Hanya 3 percobaan login admin per 5 menit
    jailThreshold: 5,
    jailDurationMs: 60 * 60 * 1e3
    // Banned 1 jam
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true, knownScanners: true },
  ipFilter: {
    whitelist: ["127.0.0.1", "::1"],
    trustProxy: true
  }
};
var INTERNAL_API = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 500 },
  // Tinggi untuk internal calls
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true },
  pathTraversal: { enabled: true },
  ipFilter: {
    whitelist: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1"]
  }
};
var WEBHOOK = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 200 },
  sqlInjection: { enabled: true, sensitivity: "medium", inspectBody: true },
  xss: { enabled: false },
  commandInjection: { enabled: true },
  pathTraversal: { enabled: false },
  payloadGuard: { enabled: true, maxBodySize: 5 * 1024 * 1024 }
};
var PUBLIC_API = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 300 },
  sqlInjection: { enabled: true, sensitivity: "low", inspectQuery: true },
  xss: { enabled: true, sensitivity: "low", inspectQuery: true },
  badBots: { enabled: true, knownScanners: true }
};
var HEALTH_CHECK = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 600 },
  // Monitoring tool sering poll
  sqlInjection: { enabled: false },
  xss: { enabled: false },
  badBots: { enabled: false }
};
var SEO = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 60 },
  sqlInjection: { enabled: false },
  xss: { enabled: false },
  badBots: { enabled: false }
  // Search engine bots harus diizinkan
};
var NEWSLETTER = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 5,
    jailDurationMs: 10 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "medium", inspectBody: true },
  xss: { enabled: true },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 1 * 1024 }
  // 1 KB
};
var CONTACT_FORM = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 3,
    // Anti-spam: 3 pesan per menit
    jailThreshold: 6,
    jailDurationMs: 10 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "medium", inspectBody: true },
  xss: { enabled: true, sensitivity: "high" },
  commandInjection: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true },
  payloadGuard: { enabled: true, maxBodySize: 100 * 1024 }
  // 100 KB
};
var CART = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 60 },
  sqlInjection: { enabled: true, inspectBody: true, inspectQuery: true },
  xss: { enabled: true },
  badBots: { enabled: true, knownScanners: true },
  payloadGuard: { enabled: true, maxBodySize: 100 * 1024 }
};
var ORDER = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 50 },
  sqlInjection: { enabled: true, sensitivity: "high", inspectQuery: true },
  xss: { enabled: false },
  pathTraversal: { enabled: true },
  badBots: { enabled: true, knownScanners: true }
};
var COUPON = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 10,
    jailThreshold: 20,
    jailDurationMs: 10 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true, inspectQuery: true },
  xss: { enabled: true },
  badBots: { enabled: true }
};
var RATING = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 10 },
  sqlInjection: { enabled: true, inspectBody: true },
  xss: { enabled: true, sensitivity: "high" },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 5 * 1024 }
  // 5 KB per review
};
var MEDIA_UPLOAD = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 10 },
  sqlInjection: { enabled: false },
  // payload binary
  xss: { enabled: false },
  pathTraversal: { enabled: true, inspectQuery: true },
  badBots: { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 100 * 1024 * 1024 }
  // 100 MB
};
var BLOG = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 20 },
  sqlInjection: { enabled: true, inspectBody: true, inspectQuery: true },
  xss: { enabled: true, sensitivity: "high" },
  // Konten HTML bisa dirender
  commandInjection: { enabled: true },
  badBots: { enabled: true, knownScanners: true },
  payloadGuard: { enabled: true, maxBodySize: 10 * 1024 * 1024 }
  // 10 MB
};
var OAUTH_CALLBACK = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 30 },
  sqlInjection: { enabled: true, sensitivity: "high", inspectQuery: true },
  xss: { enabled: true, inspectQuery: true },
  pathTraversal: { enabled: true, inspectQuery: true },
  badBots: { enabled: true }
};
var TOKEN_REFRESH = {
  mode: "enforce",
  rateLimit: {
    windowMs: 60 * 1e3,
    max: 10,
    jailThreshold: 20,
    jailDurationMs: 5 * 60 * 1e3
  },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: false },
  badBots: { enabled: true, blockEmptyUserAgent: true },
  payloadGuard: { enabled: true, maxBodySize: 4 * 1024 }
  // 4 KB
};
var API_KEY = {
  mode: "enforce",
  rateLimit: { windowMs: 60 * 1e3, max: 20 },
  sqlInjection: { enabled: true, sensitivity: "high", inspectBody: true },
  xss: { enabled: true },
  commandInjection: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true }
};
var ENDPOINT_PRESETS = {
  // Autentikasi
  LOGIN,
  REGISTER,
  LOGOUT,
  FORGOT_PASSWORD,
  CHANGE_PASSWORD,
  VERIFY_OTP,
  OAUTH_CALLBACK,
  TOKEN_REFRESH,
  API_KEY,
  // Pengguna
  PROFILE,
  FILE_UPLOAD,
  COMMENT,
  MESSAGE,
  // Data & API
  SEARCH,
  PRODUCTS,
  PRODUCT_DETAIL,
  CREATE_UPDATE,
  DELETE_DATA,
  BULK,
  // Keuangan
  PAYMENT,
  PAYMENT_WEBHOOK,
  WITHDRAW,
  // Admin & Internal
  ADMIN,
  ADMIN_LOGIN,
  INTERNAL_API,
  WEBHOOK,
  // E-Commerce
  CART,
  ORDER,
  COUPON,
  RATING,
  // Media & Konten
  MEDIA_UPLOAD,
  BLOG,
  // Publik
  PUBLIC_API,
  HEALTH_CHECK,
  SEO,
  NEWSLETTER,
  CONTACT_FORM
};

// src/index.ts
var NextGuard = class {
  engine;
  config;
  constructor(config = {}) {
    this.config = config;
    this.engine = new NextGuardEngine(config);
  }
  /**
   * Inspect a request context and return the firewall verdict
   */
  async inspect(req) {
    return this.engine.inspect(req);
  }
  /**
   * Create Next.js global middleware (`middleware.ts`)
   */
  nextMiddleware(overrideConfig) {
    return createNextGuardMiddleware({ ...this.config, ...overrideConfig });
  }
  /**
   * Protect Next.js App Router route handler (app/api/.../route.ts)
   */
  protectAppRoute(handler, overrideConfig) {
    return withNextGuard(handler, { ...this.config, ...overrideConfig });
  }
  /**
   * Protect Next.js Pages Router API handler (pages/api/...ts)
   */
  protectPagesRoute(handler, overrideConfig) {
    return withNextGuardPages(handler, { ...this.config, ...overrideConfig });
  }
  /**
   * Node.js Express / Connect middleware
   */
  express(overrideConfig) {
    return nextGuardExpress({ ...this.config, ...overrideConfig });
  }
  /**
   * Get underlying engine
   */
  getEngine() {
    return this.engine;
  }
};
var src_default = NextGuard;
/**
 * NextGuard - Web Application Firewall (WAF) & Endpoint Security for Next.js and Node.js
 *
 * @license MIT
 * @author NextGuard Team
 */

exports.BotDetector = BotDetector;
exports.CommandInjectionDetector = CommandInjectionDetector;
exports.DEFAULT_HONEYPOT_PATHS = DEFAULT_HONEYPOT_PATHS;
exports.DefensiveTarpit = DefensiveTarpit;
exports.ENDPOINT_PRESETS = ENDPOINT_PRESETS;
exports.EndpointRegistry = EndpointRegistry;
exports.HoneypotTrap = HoneypotTrap;
exports.IPFilter = IPFilter;
exports.MemoryStore = MemoryStore;
exports.NextGuard = NextGuard;
exports.NextGuardEngine = NextGuardEngine;
exports.NoSQLInjectionDetector = NoSQLInjectionDetector;
exports.PathTraversalDetector = PathTraversalDetector;
exports.PrototypePollutionDetector = PrototypePollutionDetector;
exports.RateLimiter = RateLimiter;
exports.RedisStore = RedisStore;
exports.ReputationEngine = ReputationEngine;
exports.SQLInjectionDetector = SQLInjectionDetector;
exports.SSRFDetector = SSRFDetector;
exports.XSSDetector = XSSDetector;
exports.applyGuard = applyGuard;
exports.createGuardGroup = createGuardGroup;
exports.createNextGuardMiddleware = createNextGuardMiddleware;
exports.default = src_default;
exports.defineEndpointSecurity = defineEndpointSecurity;
exports.getSecurityHeaders = getSecurityHeaders;
exports.guardExpress = guardExpress;
exports.makeEndpointId = makeEndpointId;
exports.mergeGuard = mergeGuard;
exports.nextGuardExpress = nextGuardExpress;
exports.normalizePath = normalizePath;
exports.renderBlockedHtml = renderBlockedHtml;
exports.renderBlockedJson = renderBlockedJson;
exports.withGuard = withGuard;
exports.withNextGuard = withNextGuard;
exports.withNextGuardPages = withNextGuardPages;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map