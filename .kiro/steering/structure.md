# CodeVault — Structure Steering

## Folder Layout
```
codevault/
├── .kiro/
│   ├── specs/
│   │   └── codevault.md       — full spec: requirements, design, tasks
│   ├── hooks/
│   │   ├── post-save.json     — run tests on file save
│   │   └── post-scan.json     — log scan completion
│   └── steering/
│       ├── product.md         — what CodeVault is
│       ├── tech.md            — stack and constraints
│       └── structure.md       — this file
├── src/
│   ├── scanner.js             — 15-rule vulnerability pattern engine
│   ├── advisor.js             — explanation + fix generator per vulnerability
│   ├── audit_chain.js         — SHA-256 hash-chained forensic ledger
│   ├── report_builder.js      — generates shareable HTML forensic certificate
│   └── server.js              — HTTP server + SSE live feed
├── test/
│   └── codevault.test.js      — 20+ deterministic unit tests
├── dashboard.html             — 3-page titanium cockpit
├── index.html                 — redirect to dashboard
├── package.json
├── README.md
└── .gitignore
```

## Module Responsibilities
Each module does ONE thing. No module imports another's business logic.
- scanner.js: takes a string, returns array of findings
- advisor.js: takes a finding ID, returns explanation + fix suggestion
- audit_chain.js: append-only SHA-256 ledger, verify integrity
- report_builder.js: takes scan result, returns HTML string
- server.js: HTTP orchestration only — no business logic inline

## Test File Convention
Each test group is labelled with the module name.
Tests are numbered sequentially.
Every test prints [PASS] or [FAIL] with the test name.
Final line: "Results: N passed, M failed"
