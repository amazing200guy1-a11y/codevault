# CodeVault — Engineering Specification
## Kiroween 2026 | Frankenstein Category

---

## Requirements

### User Stories
- As a developer, I want to paste my code and see every vulnerability in under 1 second
- As a security engineer, I want a cryptographic receipt proving this code was audited on a specific date
- As a compliance officer, I want to verify that an audit receipt has not been tampered with
- As a developer, I want an AI-generated explanation and fix for every finding

### Functional Requirements
1. MUST accept raw code as input (any language)
2. MUST scan against 15 vulnerability rule categories
3. MUST produce a SHA-256 hash of the scanned code + findings
4. MUST append each scan to a tamper-evident hash chain
5. MUST generate a shareable HTML forensic certificate
6. MUST verify chain integrity on demand
7. MUST stream scan events via SSE to live dashboard
8. MUST complete a scan in under 500ms

### Non-Functional Requirements
- Zero production npm dependencies
- Runs on any machine with Node.js 18+
- All crypto via Node.js stdlib only
- Deterministic: same code = same findings every time

---

## Design

### Architecture
```
Code Input (dashboard)
       │
       ▼
  POST /v1/scan
       │
       ▼
┌──────────────────────┐
│  scanner.js          │  15 vulnerability rules → findings[]
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  advisor.js          │  finding ID → explanation + fix
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  audit_chain.js      │  SHA-256 hash chain → forensic receipt
└──────────┬───────────┘
           │
       broadcast via SSE
           │
           ▼
    dashboard.html (live)
```

### Vulnerability Rules (15)
| ID | Name | Pattern |
|----|------|---------|
| V01 | SQL_INJECTION | String concat in query context |
| V02 | COMMAND_INJECTION | exec/spawn/eval with variable |
| V03 | PATH_TRAVERSAL | ../ in file operations |
| V04 | HARDCODED_SECRET | API keys, passwords, tokens in code |
| V05 | WEAK_CRYPTO | MD5, SHA1, DES, RC4 usage |
| V06 | INSECURE_RANDOM | Math.random() in security context |
| V07 | PROTOTYPE_POLLUTION | __proto__ / constructor[prototype] |
| V08 | OPEN_REDIRECT | Unvalidated redirect targets |
| V09 | REGEX_DOS | Catastrophic backtracking patterns |
| V10 | XSS_UNSAFE_HTML | innerHTML / document.write with variable |
| V11 | EVAL_INJECTION | eval() with dynamic input |
| V12 | SSRF_RISK | fetch/http with user-controlled URL |
| V13 | BROKEN_AUTH | JWT without signature verification |
| V14 | INSECURE_CORS | Access-Control-Allow-Origin: * |
| V15 | SENSITIVE_DATA_LOG | Passwords/tokens in console.log |

### Severity Scoring
- CRITICAL: V01, V02, V11 (score: 50)
- HIGH: V03, V04, V10, V12, V13 (score: 30)
- MEDIUM: V05, V06, V07, V08, V14, V15 (score: 15)
- LOW: V09 (score: 5)

### Hash Chain Entry Structure
```json
{
  "index": 0,
  "timestamp": "2026-11-02T09:00:00.000Z",
  "scan_id": "scan_abc123",
  "code_hash": "<sha256 of scanned code>",
  "findings_hash": "<sha256 of JSON.stringify(findings)>",
  "finding_count": 3,
  "severity_score": 95,
  "prev_hash": "GENESIS",
  "hash": "<sha256 of this entry minus hash field>"
}
```

---

## Tasks

### Phase 1 — Core Engine (Day 1)
- [ ] scanner.js: implement all 15 rules with regex + AST-lite patterns
- [ ] advisor.js: explanation + fix for each rule ID
- [ ] audit_chain.js: append, verify, getChain methods

### Phase 2 — Server + Tests (Day 2)
- [ ] server.js: POST /v1/scan, GET /v1/chain, GET /health, GET /v1/events (SSE)
- [ ] codevault.test.js: 20+ tests covering all modules

### Phase 3 — Dashboard (Day 3)
- [ ] dashboard.html: 3 pages (Scan, Audit Chain, Report)
- [ ] Live SSE connection to server
- [ ] Shareable forensic certificate page

### Phase 4 — Polish + Ship (Day 4)
- [ ] README.md with badges, architecture, quick start
- [ ] index.html redirect
- [ ] .gitignore
- [ ] GitHub repo + Pages
- [ ] YouTube demo video (3 min)
- [ ] Devpost submission
