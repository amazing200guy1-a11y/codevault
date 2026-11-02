# CodeVault — Forensic Code Security Scanner

![Tests](https://img.shields.io/badge/tests-22%2F22%20passing-10B981?style=flat-square&logo=checkmarx)
![Category](https://img.shields.io/badge/kiroween-frankenstein-7DD3FC?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-E11D48?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-64748B?style=flat-square)
![Built with Kiro](https://img.shields.io/badge/built%20with-Kiro%20IDE-7DD3FC?style=flat-square)

> **Frankenstein Category — Kiroween 2026**  
> Stitch together incompatible technologies: static analysis engine + AI advisory system + SHA-256 forensic audit chain = cryptographic proof that code was scanned.

## Live Demo

**[codevault dashboard →](https://amazing200guy1-a11y.github.io/codevault/dashboard.html)**

## What It Does

CodeVault is a forensic-grade code vulnerability scanner. Every scan is recorded in a SHA-256 hash-chained audit ledger — tamper-evident, cryptographically verifiable. You get a forensic receipt with `code_hash`, `chain_hash`, and `prev_hash` for every scan.

### Three Stitched-Together Technologies

| Layer | Technology | Purpose |
|---|---|---|
| Static Analysis | Custom 15-rule regex engine | Detect OWASP Top 10 patterns |
| Advisory Engine | AI-style per-rule guidance | Explain + fix each finding |
| Forensic Ledger | SHA-256 hash chain | Tamper-evident audit trail |

## Vulnerability Rules (V01–V15)

| ID | Rule | Severity | OWASP |
|---|---|---|---|
| V01 | SQL Injection | CRITICAL | A03 |
| V02 | Command Injection | CRITICAL | A03 |
| V03 | Path Traversal | HIGH | A01 |
| V04 | Hardcoded Secret | HIGH | A02 |
| V05 | Weak Crypto (MD5) | HIGH | A02 |
| V06 | Insecure Random | MEDIUM | A02 |
| V07 | Prototype Pollution | HIGH | A08 |
| V08 | Open Redirect | MEDIUM | A01 |
| V09 | ReDoS | MEDIUM | A05 |
| V10 | XSS (innerHTML) | HIGH | A03 |
| V11 | eval() Injection | CRITICAL | A03 |
| V12 | SSRF | HIGH | A10 |
| V13 | Broken Auth | MEDIUM | A07 |
| V14 | Insecure CORS | HIGH | A05 |
| V15 | Sensitive Data Logging | MEDIUM | A09 |

## Architecture

```
codevault/
├── .kiro/
│   ├── specs/codevault.md       # Engineering specification
│   ├── hooks/post-save.json     # Auto-run tests on save
│   ├── hooks/post-scan.json     # Log scan completion
│   └── steering/
│       ├── product.md           # What CodeVault is
│       ├── tech.md              # Stack & constraints
│       └── structure.md        # Folder conventions
├── src/
│   ├── scanner.js               # 15-rule static analysis engine
│   ├── advisor.js               # Per-rule advisory (explanation + fix)
│   ├── audit_chain.js           # SHA-256 hash-chained forensic ledger
│   └── server.js                # HTTP server + SSE live feed
├── test/
│   └── codevault.test.js        # 22 tests (all passing)
├── dashboard.html               # 3-page titanium UI (Scan | Chain | Report)
└── index.html                   # Redirect
```

## API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/scan` | Scan code — returns findings + forensic receipt |
| `GET` | `/v1/chain` | Full audit chain with integrity status |
| `GET` | `/v1/events` | SSE live feed (snapshot + scan events) |
| `GET` | `/health` | Server health check |

### Scan Request

```bash
curl -X POST http://127.0.0.1:3000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"code":"const q = \"SELECT * FROM users WHERE id = \" + id;"}'
```

### Scan Response (excerpt)

```json
{
  "scan_id": "cv_1a2b3c4d",
  "findings": [{ "rule_id": "V01", "name": "SQL Injection", "severity": "CRITICAL", "line": 1 }],
  "severity_score": 60,
  "risk_level": "CRITICAL",
  "chain": {
    "hash": "sha256:abc123...",
    "prev_hash": "sha256:def456...",
    "code_hash": "sha256:ghi789..."
  }
}
```

## Quick Start

```bash
git clone https://github.com/amazing200guy1-a11y/codevault.git
cd codevault
node test/codevault.test.js   # 22/22 tests
node src/server.js            # Start server on :3000
# Open dashboard.html in browser
```

No npm install required. Node.js stdlib only.

## Test Results

```
Results: 22 passed, 0 failed
All CodeVault Security Modules Verified.
```

## Built With Kiro IDE

This project was built using Kiro IDE for Kiroween 2026. The `.kiro/` directory contains:
- **Specs**: Full engineering requirements and design
- **Hooks**: Automated test runs on file save
- **Steering docs**: Product, tech stack, and structure context

## License

MIT — see [LICENSE](LICENSE)
