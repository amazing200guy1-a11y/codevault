# CodeVault — Product Steering

## What It Is
CodeVault is an AI-powered code vulnerability scanner that produces cryptographically signed, tamper-evident forensic audit receipts for every scan. It is the only code scanner in the world where the result is a verifiable cryptographic claim — not just a report you can edit.

## Who It Is For
- Developers who need to prove their code was audited before deployment
- Security teams who need forensic evidence of code review
- Open source maintainers who want to show their repo is clean
- Compliance officers who need tamper-proof audit trails

## The Core Promise
Paste your code. Get vulnerabilities. Get a SHA-256 forensic receipt that proves — mathematically — what was found, when, and that the record has not been altered since.

## What Makes It Frankenstein
Four technologies that have never been combined into one tool:
1. Static analysis (pattern-based vulnerability detection)
2. AI advisory engine (explains each vulnerability + generates a fix)
3. SHA-256 hash-chained forensic ledger (tamper-evident receipts)
4. Shareable report page (one link proves the audit happened)

## What It Is NOT
- It is not a replacement for Snyk or SonarQube in CI/CD pipelines
- It is not a cloud service with user accounts
- It is not an AI that writes code from scratch

## Core Values
- Every claim is verifiable. No hand-waving.
- No external dependencies. Runs anywhere Node.js runs.
- Fast. A scan completes in under 100ms.
- The receipt is the product. Not just a pretty dashboard.
