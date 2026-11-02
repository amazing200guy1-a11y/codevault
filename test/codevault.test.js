'use strict';

/**
 * CodeVault — Automated Test Suite
 * 22 deterministic tests covering all modules.
 * No external test frameworks. Pure Node.js.
 */

const { scan, RULES } = require('../src/scanner');
const { getAdvisory, enrichFindings } = require('../src/advisor');
const AuditChain = require('../src/audit_chain');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`  [FAIL] ${name}`);
    console.log(`         ${e.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

function assertEqual(a, b, msg) {
  if (a !== b) throw new Error(msg || `Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

// ─────────────────────────────────────────────────────────
console.log('\n================================================');
console.log('  CodeVault — Forensic Security Scanner Tests');
console.log('================================================\n');

// ── Scanner: clean code ──────────────────────────────────
console.log('[ Scanner: Clean Code ]');

test('Clean code returns zero findings', () => {
  const result = scan('function add(a, b) { return a + b; }');
  assertEqual(result.finding_count, 0);
  assertEqual(result.risk_level, 'CLEAN');
});

test('Clean code has severity score of 0', () => {
  const result = scan('const x = 1; console.log(x);');
  assertEqual(result.severity_score, 0);
});

test('Scanner reports correct line count', () => {
  const code = 'line1\nline2\nline3';
  const result = scan(code);
  assertEqual(result.scanned_lines, 3);
});

test('Scanner evaluates all 15 rules', () => {
  const result = scan('');
  assertEqual(result.rules_evaluated, 15);
});

// ── Scanner: vulnerability detection ────────────────────
console.log('\n[ Scanner: Vulnerability Detection ]');

test('V01 SQL injection detected', () => {
  const code = `db.query("SELECT * FROM users WHERE id = " + req.params.id);`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V01'), 'V01 not found');
});

test('V02 Command injection detected', () => {
  const code = `exec('ls ' + req.body.dir);`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V02'), 'V02 not found');
});

test('V04 Hardcoded secret detected', () => {
  const code = `const apiKey = "sk-abcdefghijklmnopqrstuvwxyz123456";`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V04'), 'V04 not found');
});

test('V05 Weak crypto (MD5) detected', () => {
  const code = `crypto.createHash('md5').update(data).digest('hex');`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V05'), 'V05 not found');
});

test('V06 Insecure random detected', () => {
  const code = `const token = Math.random().toString(36);`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V06'), 'V06 not found');
});

test('V10 XSS via innerHTML detected', () => {
  const code = `element.innerHTML = userInput;`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V10'), 'V10 not found');
});

test('V11 eval() injection detected', () => {
  const code = `const result = eval(req.body.expression);`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V11'), 'V11 not found');
});

test('V14 Insecure CORS detected', () => {
  const code = `res.setHeader('Access-Control-Allow-Origin', '*');`;
  const result = scan(code);
  assert(result.findings.some(f => f.rule_id === 'V14'), 'V14 not found');
});

test('CRITICAL severity score >= 50 for critical findings', () => {
  const code = `eval(req.body.code);`;
  const result = scan(code);
  assert(result.severity_score >= 50, `Score was ${result.severity_score}`);
});

test('Risk level is CRITICAL for high score', () => {
  const code = `eval(req.body.x); exec(req.body.cmd); db.query("SELECT " + req.params.id);`;
  const result = scan(code);
  assertEqual(result.risk_level, 'CRITICAL');
});

// ── Advisor ──────────────────────────────────────────────
console.log('\n[ Advisor: Advisory Engine ]');

test('Advisory returned for V01', () => {
  const advisory = getAdvisory('V01');
  assert(advisory.title === 'SQL Injection', `Got: ${advisory.title}`);
  assert(advisory.fix.length > 0, 'fix is empty');
  assert(advisory.cwe.startsWith('CWE-'), 'CWE missing');
});

test('Advisory returned for all 15 rules', () => {
  const ids = ['V01','V02','V03','V04','V05','V06','V07','V08','V09','V10','V11','V12','V13','V14','V15'];
  for (const id of ids) {
    const a = getAdvisory(id);
    assert(a.title !== 'Unknown Rule', `Missing advisory for ${id}`);
  }
});

test('enrichFindings adds advisory to each finding', () => {
  const code = `eval(req.body.x);`;
  const result = scan(code);
  const enriched = enrichFindings(result.findings);
  assert(enriched.length > 0, 'No findings to enrich');
  assert(enriched[0].advisory, 'Advisory not attached');
  assert(enriched[0].advisory.fix.length > 0, 'Fix is empty');
});

// ── Audit Chain ──────────────────────────────────────────
console.log('\n[ Audit Chain: Forensic Ledger ]');

test('Chain starts with GENESIS tip hash', () => {
  const chain = new AuditChain();
  assertEqual(chain.currentTipHash, 'GENESIS');
});

test('Appending entry produces valid SHA-256 hash', () => {
  const chain = new AuditChain();
  const mockResult = { findings: [], finding_count: 0, severity_score: 0, risk_level: 'CLEAN' };
  const entry = chain.append('scan_test_001', 'const x = 1;', mockResult);
  assert(entry.hash.length === 64, `Hash length: ${entry.hash.length}`);
  assert(entry.prev_hash === 'GENESIS', 'First entry prev_hash should be GENESIS');
});

test('Chain of 3 entries verifies as intact', () => {
  const chain = new AuditChain();
  const mock = { findings: [], finding_count: 0, severity_score: 0, risk_level: 'CLEAN' };
  chain.append('s1', 'code1', mock);
  chain.append('s2', 'code2', mock);
  chain.append('s3', 'code3', mock);
  const result = chain.verify();
  assert(result.intact === true, `Chain not intact: ${JSON.stringify(result)}`);
  assertEqual(result.entry_count, 3);
});

test('Tampered entry breaks chain verification', () => {
  const chain = new AuditChain();
  const mock = { findings: [], finding_count: 0, severity_score: 0, risk_level: 'CLEAN' };
  chain.append('s1', 'code1', mock);
  chain.append('s2', 'code2', mock);
  // Tamper with entry 0
  chain.entries[0].finding_count = 999;
  const result = chain.verify();
  assert(result.intact === false, 'Tamper not detected');
});

test('getChain returns entries in reverse order (newest first)', () => {
  const chain = new AuditChain();
  const mock = { findings: [], finding_count: 0, severity_score: 0, risk_level: 'CLEAN' };
  chain.append('first', 'code', mock);
  chain.append('second', 'code', mock);
  const entries = chain.getChain();
  assertEqual(entries[0].scan_id, 'second', 'Newest not first');
});

// ─────────────────────────────────────────────────────────
console.log('\n================================================');
console.log(`  Results: ${passed} passed, ${failed} failed`);
if (failed === 0) console.log('  All CodeVault Security Modules Verified.');
console.log('================================================\n');

process.exit(failed > 0 ? 1 : 0);
