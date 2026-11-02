'use strict';

/**
 * CodeVault — AI Advisory Engine
 * For each vulnerability rule ID, returns a human-readable explanation
 * and a concrete code fix. No external dependencies.
 */

const ADVISORIES = {
  V01: {
    title: 'SQL Injection',
    explanation: 'Your code constructs SQL queries by concatenating strings with user-supplied input. An attacker can inject malicious SQL to read, modify, or delete your entire database.',
    fix: 'Use parameterised queries or prepared statements. Never concatenate user input directly into SQL strings.',
    example_fix: `// UNSAFE\ndb.query("SELECT * FROM users WHERE id = " + req.params.id);\n\n// SAFE\ndb.query("SELECT * FROM users WHERE id = ?", [req.params.id]);`,
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-89',
  },
  V02: {
    title: 'Command Injection',
    explanation: 'Your code passes user-controlled input directly to a shell command. An attacker can terminate your command and inject arbitrary OS commands, gaining full system access.',
    fix: 'Never pass user input to exec/spawn directly. Use argument arrays with spawn() instead of exec(), and whitelist allowed values.',
    example_fix: `// UNSAFE\nexec('convert ' + req.body.file);\n\n// SAFE\nspawn('convert', [sanitisedFilename], { shell: false });`,
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-78',
  },
  V03: {
    title: 'Path Traversal',
    explanation: 'Your code constructs a file path using user input without validation. An attacker can use ../ sequences to escape the intended directory and read sensitive files like /etc/passwd.',
    fix: 'Resolve the full path with path.resolve(), then verify it starts with your intended base directory before using it.',
    example_fix: `// SAFE\nconst base = path.resolve('./uploads');\nconst target = path.resolve(base, req.params.file);\nif (!target.startsWith(base)) throw new Error('Path traversal detected');`,
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-22',
  },
  V04: {
    title: 'Hardcoded Secret',
    explanation: 'A secret key, API token, or password is hardcoded in your source code. Anyone with access to your repository — including public GitHub viewers — can steal and use these credentials.',
    fix: 'Move all secrets to environment variables. Use a .env file locally and a secrets manager (AWS Secrets Manager, Vault) in production. Add .env to .gitignore immediately.',
    example_fix: `// UNSAFE\nconst apiKey = "sk-abc123...";\n\n// SAFE\nconst apiKey = process.env.API_KEY;\nif (!apiKey) throw new Error('API_KEY not set');`,
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-798',
  },
  V05: {
    title: 'Weak Cryptographic Algorithm',
    explanation: 'MD5 and SHA-1 are cryptographically broken. Collisions can be computed in seconds. Using them for password hashing, integrity checks, or signatures provides no real security.',
    fix: 'Use SHA-256 or SHA-3 for hashing. Use bcrypt, scrypt, or Argon2 for passwords. Use AES-256-GCM for encryption.',
    example_fix: `// UNSAFE\ncrypto.createHash('md5').update(data).digest('hex');\n\n// SAFE\ncrypto.createHash('sha256').update(data).digest('hex');`,
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-327',
  },
  V06: {
    title: 'Insecure Random Number Generator',
    explanation: 'Math.random() is not cryptographically secure. Its output is predictable. Never use it to generate tokens, session IDs, nonces, salts, or any security-sensitive value.',
    fix: 'Use crypto.randomBytes() for all security-sensitive random values.',
    example_fix: `// UNSAFE\nconst token = Math.random().toString(36);\n\n// SAFE\nconst token = crypto.randomBytes(32).toString('hex');`,
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-338',
  },
  V07: {
    title: 'Prototype Pollution',
    explanation: 'Your code assigns to __proto__ or modifies Object.prototype via user-controlled keys. An attacker can inject properties into the base Object prototype, affecting every object in the application.',
    fix: 'Use Object.create(null) for maps that accept user keys. Validate and sanitise object keys. Never merge user input directly into objects without a safelist.',
    example_fix: `// UNSAFE\nObject.assign(target, req.body);\n\n// SAFE\nconst allowed = ['name', 'email'];\nconst safe = Object.fromEntries(\n  Object.entries(req.body).filter(([k]) => allowed.includes(k))\n);`,
    owasp: 'A08:2021 – Software and Data Integrity Failures',
    cwe: 'CWE-1321',
  },
  V08: {
    title: 'Open Redirect',
    explanation: 'Your code redirects users to a URL derived from user input without validation. Attackers use this for phishing — they send a legitimate-looking link that redirects to a malicious site.',
    fix: 'Maintain a safelist of allowed redirect destinations. Never redirect to arbitrary user-supplied URLs.',
    example_fix: `// UNSAFE\nres.redirect(req.query.next);\n\n// SAFE\nconst allowed = ['/dashboard', '/profile'];\nconst next = allowed.includes(req.query.next) ? req.query.next : '/';\nres.redirect(next);`,
    owasp: 'A01:2021 – Broken Access Control',
    cwe: 'CWE-601',
  },
  V09: {
    title: 'Regular Expression Denial of Service (ReDoS)',
    explanation: 'This regex may contain catastrophic backtracking patterns. A crafted input string can cause exponential matching time, hanging your server for minutes or longer.',
    fix: 'Simplify nested quantifiers. Use possessive quantifiers or atomic groups where supported. Test regex against adversarial input with a tool like safe-regex.',
    example_fix: `// POTENTIALLY UNSAFE (nested quantifiers)\n/(a+)+/.test(input);\n\n// SAFER\n/a+/.test(input); // simplify where possible`,
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-1333',
  },
  V10: {
    title: 'Cross-Site Scripting (XSS) via Unsafe HTML',
    explanation: 'Your code sets innerHTML or uses document.write with dynamic data. An attacker can inject malicious script tags that execute in victims\' browsers, stealing cookies and sessions.',
    fix: 'Use textContent instead of innerHTML for plain text. If you need HTML, sanitise with DOMPurify or a trusted library before insertion.',
    example_fix: `// UNSAFE\nel.innerHTML = userData;\n\n// SAFE\nel.textContent = userData; // for plain text\n// OR\nel.innerHTML = DOMPurify.sanitize(userData); // for HTML`,
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-79',
  },
  V11: {
    title: 'Code Injection via eval()',
    explanation: 'eval() or new Function() is called with dynamic or user-supplied input. This is equivalent to remote code execution — the attacker can run any JavaScript in your Node.js process.',
    fix: 'Never eval user input. If you need dynamic computation, use a safe expression parser or restrict to a controlled DSL.',
    example_fix: `// UNSAFE\nconst result = eval(req.body.expression);\n\n// SAFE — use a sandboxed parser instead\n// e.g., mathjs.evaluate(expression) with input validation`,
    owasp: 'A03:2021 – Injection',
    cwe: 'CWE-95',
  },
  V12: {
    title: 'Server-Side Request Forgery (SSRF)',
    explanation: 'Your server makes HTTP requests to URLs derived from user input. An attacker can point this at internal services (localhost, cloud metadata endpoints like 169.254.169.254) to steal credentials or pivot inside your network.',
    fix: 'Validate and allowlist destination URLs. Block private IP ranges. Never forward user-supplied URLs directly to fetch/http.get.',
    example_fix: `// UNSAFE\nawait fetch(req.query.url);\n\n// SAFE\nconst allowed = ['https://api.trusted.com'];\nif (!allowed.some(a => req.query.url.startsWith(a))) throw new Error('SSRF blocked');`,
    owasp: 'A10:2021 – Server-Side Request Forgery',
    cwe: 'CWE-918',
  },
  V13: {
    title: 'Broken Authentication — JWT Not Verified',
    explanation: 'Your code decodes a JWT without verifying its signature. An attacker can forge any token by base64-encoding a crafted payload — no secret key needed. You are trusting unverified claims.',
    fix: 'Always use jwt.verify() with your secret, never jwt.decode() alone for authentication decisions.',
    example_fix: `// UNSAFE\nconst payload = jwt.decode(token); // no signature check\n\n// SAFE\nconst payload = jwt.verify(token, process.env.JWT_SECRET);`,
    owasp: 'A07:2021 – Identification and Authentication Failures',
    cwe: 'CWE-347',
  },
  V14: {
    title: 'Insecure CORS Configuration',
    explanation: 'Your server allows requests from any origin (*). Combined with credentials, this lets malicious websites make authenticated requests on behalf of your users.',
    fix: 'Specify exact allowed origins. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.',
    example_fix: `// UNSAFE\nres.setHeader('Access-Control-Allow-Origin', '*');\n\n// SAFE\nconst allowed = ['https://yourdomain.com'];\nif (allowed.includes(req.headers.origin)) {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n}`,
    owasp: 'A05:2021 – Security Misconfiguration',
    cwe: 'CWE-942',
  },
  V15: {
    title: 'Sensitive Data in Logs',
    explanation: 'Passwords, tokens, or private keys are being written to console.log. Log files are often stored insecurely, aggregated to third-party services, and retained long-term. This exposes credentials.',
    fix: 'Never log secrets. Redact sensitive fields before logging. Use a structured logger with field-level redaction.',
    example_fix: `// UNSAFE\nconsole.log('User login:', { email, password });\n\n// SAFE\nconsole.log('User login:', { email, password: '[REDACTED]' });`,
    owasp: 'A02:2021 – Cryptographic Failures',
    cwe: 'CWE-532',
  },
};

/**
 * Get advisory for a specific rule ID.
 * @param {string} ruleId - e.g. 'V01'
 * @returns {object} Advisory with title, explanation, fix, example
 */
function getAdvisory(ruleId) {
  return ADVISORIES[ruleId] || {
    title: 'Unknown Rule',
    explanation: 'No advisory available for this rule.',
    fix: 'Review the flagged code manually.',
    example_fix: '',
    owasp: 'N/A',
    cwe: 'N/A',
  };
}

/**
 * Enrich scan findings with full advisory detail.
 * @param {Array} findings - from scanner.scan()
 * @returns {Array} findings with advisory field added
 */
function enrichFindings(findings) {
  return findings.map(f => ({
    ...f,
    advisory: getAdvisory(f.rule_id),
  }));
}

module.exports = { getAdvisory, enrichFindings, ADVISORIES };
