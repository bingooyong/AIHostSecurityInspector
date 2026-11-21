# Frontend Development Guidelines

Package: frontend (frontend/); layer: local React + TypeScript console. A lockfile, lint/typecheck/test/build scripts, and isolated pages exist. This is not an enterprise web deployment, platform login, or Playwright-vs-production acceptance.

## Pre-Development Checklist

- [Directory structure](directory-structure.md): required before creating the frontend package.
- [Component guidelines](component-guidelines.md), [hooks](hook-guidelines.md), [state](state-management.md): required for UI work.
- [Quality](quality-guidelines.md) and [type safety](type-safety.md): required for any TypeScript.
- Read `docs/02-architecture/REPOSITORY-LAYOUT.md`, `docs/03-sdd` API/CLI contracts, and `docs/04-security/SECURITY-BOUNDARIES.md`. Do not copy Go authorization, rule evaluation, or approval decisions into the browser.

## Quality Check

HOSTSEC-34 is PARTIAL: local pages for assets/jobs/evidence/rules/approvals, plus lint/typecheck/test/build gates. Authorization remains in Go. Playwright against a live API, platform identity, and production hosting remain unverified.

## Existing examples

None. Consume versioned `schemas/` and the future Web API only. Skills/MCP clients live in `integrations/`, not in this UI.
