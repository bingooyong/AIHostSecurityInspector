# Frontend Development Guidelines

Package: frontend (frontend/); layer: planned React + TypeScript client. No `frontend/` tree, package.json, or running UI exists. These files capture HostSec WP7 contracts so a future implementation does not invent a second security kernel.

## Pre-Development Checklist

- [Directory structure](directory-structure.md): required before creating the frontend package.
- [Component guidelines](component-guidelines.md), [hooks](hook-guidelines.md), [state](state-management.md): required for UI work.
- [Quality](quality-guidelines.md) and [type safety](type-safety.md): required for any TypeScript.
- Read `docs/02-architecture/REPOSITORY-LAYOUT.md`, `docs/03-sdd` API/CLI contracts, and `docs/04-security/SECURITY-BOUNDARIES.md`. Do not copy Go authorization, rule evaluation, or approval decisions into the browser.

## Quality Check

Frontend implementation (HOSTSEC-33/34/35) is PLANNED. Until then, do not add an empty npm project, CI job that reports PASS without sources, or generated types that bypass server validation. When WP7 starts, register the real frontend package in Trellis and add lockfile, lint, typecheck, test, and build gates.

## Existing examples

None. Consume versioned `schemas/` and the future Web API only. Skills/MCP clients live in `integrations/`, not in this UI.
