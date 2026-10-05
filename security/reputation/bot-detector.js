'use strict';

const MALICIOUS_UA_PATTERNS = [
  /sqlmap/i, /nikto/i, /nessus/i, /masscan/i, /zgrab/i, /nmap/i,
  /nuclei/i, /hydra/i, /medusa/i, /metasploit/i, /burpsuite/i, /dirbuster/i,
  /gobuster/i, /wfuzz/i, /acunetix/i, /openvas/i, /havij/i, /w3af/i,
  /skipfish/i, /appscan/i, /webinspect/i, /httperf/i, /ab\//i, /siege\//i,
  /wrk\//i, /vegeta/i, /k6\//i, /locust/i, /python-requests/i,
  /python-urllib/i, /go-http-client/i, /curl\/7\.[0-2]/i, /libwww-perl/i,
  /masscan\//i, /zmap/i, /shodan/i, /censys/i, /stretchr/i, /dirsearch/i,
  /feroxbuster/i, /ffuf/i, /httprint/i, /grabber/i, /arachni/i,
];

function checkBot(userAgent) {
  if (!userAgent || typeof userAgent !== 'string') return { isBot: false, pattern: null };
  for (const pattern of MALICIOUS_UA_PATTERNS) {
    if (pattern.test(userAgent)) {
      return { isBot: true, pattern: pattern.toString() };
    }
  }
  return { isBot: false, pattern: null };
}

module.exports = {
  checkBot,
  MALICIOUS_UA_PATTERNS,
};
