'use strict';

/**
 * CodeVault — Vulnerability Scanner Engine
 * 15-rule static analysis engine. Deterministic: same input = same output.
 * No external dependencies. Pure Node.js stdlib.
 */

const RULES = [
  {
    id: 'V01',
    name: 'SQL_INJECTION',
    severity: 'CRITICAL',
    score: 50,
    description: 'String concatenation in SQL query context detected.',
    patterns: [
      /(['"`]\s*\+\s*\w+|\w+\s*\+\s*['"`])\s*(?:WHERE|FROM|SELECT|INSERT|UPDATE|DELETE|DROP)/gi,
      /query\s*[=+]\s*['"`][^'"`;]*\$\{/gi,
      /(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?\+\s*(?:req\.|request\.|params\.|body\.|query\.)/gi,
    ]
  },
  {
    id: 'V02',
    name: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    score: 50,
    description: 'exec/spawn/execSync called with dynamic or user-controlled input.',
    patterns: [
      /(?:exec|execSync|spawn|spawnSync|execFile)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.|input|userInput|\$\{)/gi,
      /child_process.*exec.*\+/gi,
      /shell\s*=\s*true.*(?:req\.|params\.)/gi,
    ]
  },
  {
    id: 'V03',
    name: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    score: 30,
    description: 'File path constructed with user input — directory traversal risk.',
    patterns: [
      /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|unlink|rmdir)\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
      /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|unlink|rmdir)\s*\([^)]*\.\.\//gi,
      /path\.join\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
      /\.\.\//g,
    ]
  },
  {
    id: 'V04',
    name: 'HARDCODED_SECRET',
    severity: 'HIGH',
    score: 30,
    description: 'Hardcoded API key, password, or secret token detected in source code.',
    patterns: [
      /(?:api_?key|apikey|secret|password|passwd|token|auth_token|access_token)\s*[:=]\s*['"`][a-zA-Z0-9_\-]{8,}['"`]/gi,
      /REDACTED_sk-[a-zA-Z0-9_\-]{20,}/gi,
      /ghp_[a-zA-Z0-9]{20,}/gi,
      /AKIA[0-9A-Z]{16}/gi,
      /-----BEGIN\s+(?:RSA|EC|PRIVATE)\s+KEY-----/gi,
    ]
  },
  {
    id: 'V05',
    name: 'WEAK_CRYPTO',
    severity: 'MEDIUM',
    score: 15,
    description: 'Weak or broken cryptographic algorithm in use (MD5, SHA1, DES, RC4).',
    patterns: [
      /createHash\s*\(\s*['"`](?:md5|sha1|sha-1|des|rc4)['"`]\s*\)/gi,
      /(?:MD5|SHA1|DES|RC4)\s*\(/gi,
      /crypto\.createCipher\s*\(\s*['"`](?:des|rc4|bf)/gi,
    ]
  },
  {
    id: 'V06',
    name: 'INSECURE_RANDOM',
    severity: 'MEDIUM',
    score: 15,
    description: 'Math.random() used in a security-sensitive context (tokens, IDs, salts).',
    patterns: [
      /Math\.random\(\)\s*(?:\*|\.toString).*(?:token|secret|key|salt|id|nonce|session)/gi,
      /(?:token|secret|key|salt|nonce|session)\s*=.*Math\.random/gi,
    ]
  },
  {
    id: 'V07',
    name: 'PROTOTYPE_POLLUTION',
    severity: 'MEDIUM',
    score: 15,
    description: '__proto__ or constructor.prototype assignment detected — prototype pollution risk.',
    patterns: [
      /\.__proto__\s*=/gi,
      /\['__proto__'\]\s*=/gi,
      /constructor\s*\.\s*prototype\s*\[/gi,
      /Object\.assign\s*\(\s*(?:{}|\[\])\s*,.*req\./gi,
    ]
  },
  {
    id: 'V08',
    name: 'OPEN_REDIRECT',
    severity: 'HIGH',
    score: 30,
    description: 'Redirect target constructed from user input without validation.',
    patterns: [
      /res\.redirect\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
      /window\.location\s*=\s*.*(?:params|query|search|hash)/gi,
      /location\.href\s*=\s*(?:req\.|params\.|body\.)/gi,
    ]
  },
  {
    id: 'V09',
    name: 'REGEX_DOS',
    severity: 'LOW',
    score: 5,
    description: 'Potentially catastrophic backtracking regex detected (ReDoS risk).',
    patterns: [
      /\/\([^)]*\+\)[^/]*\+\//g,
      /\/\(\.\*\)\+\//g,
      /\/\([a-zA-Z]+\+\)+\//g,
      /new RegExp\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
    ]
  },
  {
    id: 'V10',
    name: 'XSS_UNSAFE_HTML',
    severity: 'HIGH',
    score: 30,
    description: 'innerHTML or document.write used with dynamic/user data — XSS risk.',
    patterns: [
      /\.innerHTML\s*=\s*(?!['"`]<)/gi,
      /\.innerHTML\s*\+=\s*/gi,
      /document\.write\s*\([^)]*(?:req\.|params\.|body\.|query\.|\$\{)/gi,
      /\.outerHTML\s*=\s*(?!['"`]<)/gi,
    ]
  },
  {
    id: 'V11',
    name: 'EVAL_INJECTION',
    severity: 'CRITICAL',
    score: 50,
    description: 'eval() or Function() called with dynamic input — remote code execution risk.',
    patterns: [
      /eval\s*\([^)]*(?:req\.|params\.|body\.|query\.|\$\{|input|data)/gi,
      /new\s+Function\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
      /setTimeout\s*\([^,)]*(?:req\.|params\.)/gi,
    ]
  },
  {
    id: 'V12',
    name: 'SSRF_RISK',
    severity: 'HIGH',
    score: 30,
    description: 'HTTP request made to user-controlled URL — Server-Side Request Forgery risk.',
    patterns: [
      /(?:fetch|axios\.get|axios\.post|http\.get|request)\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
      /new URL\s*\([^)]*(?:req\.|params\.|body\.|query\.)/gi,
    ]
  },
  {
    id: 'V13',
    name: 'BROKEN_AUTH',
    severity: 'HIGH',
    score: 30,
    description: 'JWT decoded without signature verification, or token compared insecurely.',
    patterns: [
      /jwt\.decode\s*\([^)]*\)(?!.*verify)/gi,
      /base64.*split\s*\(\s*['"`.'"]\s*\)\s*\[1\]/gi,
      /token\s*===?\s*(?:req\.|params\.|body\.)/gi,
    ]
  },
  {
    id: 'V14',
    name: 'INSECURE_CORS',
    severity: 'MEDIUM',
    score: 15,
    description: 'CORS configured to allow all origins (*) without restriction.',
    patterns: [
      /Access-Control-Allow-Origin['":\s,)]*\*/gi,
      /['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*/gi,
      /origin\s*:\s*['"`]\*['"`]/gi,
      /cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*['"`]/gi,
      /setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*/gi,
    ]
  },
  {
    id: 'V15',
    name: 'SENSITIVE_DATA_LOG',
    severity: 'MEDIUM',
    score: 15,
    description: 'Password, token, or secret key logged to console — credential exposure risk.',
    patterns: [
      /console\.\w+\s*\([^)]*(?:password|passwd|secret|token|api_?key|private_?key)/gi,
      /log\s*\([^)]*(?:password|passwd|secret|token|api_?key)/gi,
    ]
  },
];

/**
 * Scan source code against all 15 vulnerability rules.
 * @param {string} code - Raw source code to scan
 * @returns {object} Scan result with findings, scores, and metadata
 */
function scan(code) {
  if (typeof code !== 'string') throw new TypeError('code must be a string');

  const lines = code.split('\n');
  const findings = [];
  let totalScore = 0;

  for (const rule of RULES) {
    for (const pattern of rule.patterns) {
      // Reset lastIndex for global regexes
      pattern.lastIndex = 0;
      let match;
      const seen = new Set();

      // Line-by-line scan for accurate line numbers
      lines.forEach((line, lineIndex) => {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          const key = `${rule.id}:${lineIndex + 1}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              rule_id: rule.id,
              rule_name: rule.name,
              severity: rule.severity,
              score: rule.score,
              line: lineIndex + 1,
              snippet: line.trim().substring(0, 120),
            });
            totalScore += rule.score;
          }
        }
        pattern.lastIndex = 0;
      });
    }
  }

  // Deduplicate: keep highest-score finding per rule per line
  const dedupMap = new Map();
  for (const f of findings) {
    const key = `${f.rule_id}:${f.line}`;
    if (!dedupMap.has(key) || dedupMap.get(key).score < f.score) {
      dedupMap.set(key, f);
    }
  }
  const dedupedFindings = Array.from(dedupMap.values())
    .sort((a, b) => b.score - a.score || a.line - b.line);

  const realScore = dedupedFindings.reduce((s, f) => s + f.score, 0);

  return {
    finding_count: dedupedFindings.length,
    severity_score: realScore,
    risk_level: realScore === 0 ? 'CLEAN'
      : realScore < 30 ? 'LOW'
      : realScore < 80 ? 'MEDIUM'
      : realScore < 150 ? 'HIGH'
      : 'CRITICAL',
    findings: dedupedFindings,
    scanned_lines: lines.length,
    rules_evaluated: RULES.length,
  };
}

module.exports = { scan, RULES };
