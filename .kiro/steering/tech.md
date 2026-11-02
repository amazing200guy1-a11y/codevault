# CodeVault — Tech Steering

## Stack
- **Runtime:** Node.js (v18+), stdlib only — zero production npm dependencies
- **Frontend:** Vanilla JS + HTML — no React, no Vue, no bundler
- **Fonts:** JetBrains Mono (telemetry/code), Outfit (headings) via Google Fonts CDN
- **Crypto:** Node.js built-in `crypto` module (SHA-256 for hash chain)
- **HTTP:** Node.js built-in `http` module
- **Tests:** Custom test runner (no Jest, no Mocha) — same pattern as SentinelGate

## Design System
- Background: #04070D (page), #080C14 (secondary)
- Cards: gradient #232C3B → #171E2A → #0F131C
- Border: rgba(200,220,240,0.18), inset rgba(200,220,240,0.07)
- Shadow: 0 8px 32px rgba(0,0,0,0.6)
- Accent: emerald #10B981, crimson #E11D48, amber #F59E0B, ice #7DD3FC
- NO emoji in UI. SVG icons only.
- border-radius: 6px cards, 3px pills

## Constraints
- No external API calls at runtime (scanner runs locally)
- No npm packages in production — package.json only has devDependencies if needed
- All crypto must use Node.js built-in `crypto` — never Math.random() for security
- Scanner rules must be deterministic — same input always produces same output
- Hash chain must be append-only — no mutation of existing entries

## File Naming
- snake_case for all JS modules
- kebab-case for HTML files
- UPPER_CASE for constants
- camelCase for functions and variables

## Port
- Server runs on port 3000
- SSE live feed on GET /v1/events
- Scan endpoint: POST /v1/scan
- Chain endpoint: GET /v1/chain
- Health: GET /health
