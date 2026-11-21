# Quality Guidelines

## 1. Scope / trigger

Lint, typecheck, unit, and Playwright gates for the future frontend package.

## 2. Signatures

Required scripts: `lint`, `typecheck`, `test`, `build`, `e2e`. `make check` runs them after `npm ci`. Playwright against the loopback hostsec API exists; HOSTSEC-34 stays PARTIAL until platform identity and a hosted API are accepted.

## 3. Contracts

- No `any` for schema payloads; unknown extras fail parsing.
- Accessibility: findings and approvals are keyboard reachable.
- Logging redacts tokens, host output, and file paths from raw evidence.
- Feature flags cannot enable scan/remediation in the UI before the backend capability exists.

## 4. Validation and errors

A typecheck-only change is not product acceptance. E2E against production or customer hosts is forbidden.

## 5. Good / base / bad

Good: fixture-driven Playwright. Bad: snapshots of production findings, or skipping typecheck in CI.

## 6. Tests required

Empty, loading, error, 403, and partial-scan journeys for every feature that HOSTSEC-34 implements.

## 7. Wrong vs correct

Wrong: mark HOSTSEC-34 IMPLEMENTED because lint/typecheck/test/build/Playwright-loopback pass locally. Correct: keep PARTIAL until server-enforced platform identity and hosted API acceptance exist.
