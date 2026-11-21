# Directory Structure

## 1. Scope / trigger

Independent React + TypeScript app under repository `frontend/`. HOSTSEC-34 local slice has started; do not treat this as enterprise UI acceptance.

## 2. Signatures

Future npm scripts: `lint`, `typecheck`, `test`, `build`. The UI talks only to the versioned Web API; it has no SSH, collector, or SQLite access.

## 3. Contracts

When implemented, keep:

```
frontend/
  package.json
  package-lock.json
  src/app/            # routes and layout
  src/features/       # assets, plans, evidence, approvals, reports
  src/shared/         # design-system primitives, API client, schema types
  tests/              # Playwright and unit tests
```

Feature folders own their pages and local hooks. Shared security decisions stay in Go.

## 4. Validation and errors

| Condition | Required outcome |
|---|---|
| empty package.json / no lockfile | fail WP7 acceptance |
| UI hiding a button as the only authorization | fail security review |
| importing Go source or embedding rule YAML | fail layout/boundary gates |

## 5. Good / base / bad

Good: typed client generated from OpenAPI/Schema, server-enforced RBAC. Base: feature folders matching product centers in the PRD. Bad: utils dumping secrets into localStorage, or a mock API that always returns PASS findings.

## 6. Tests required

Playwright against an isolated stub API covering empty, forbidden, loading, and error states. No production host data.

## 7. Wrong vs correct

Wrong: create `frontend/` now to mark bootstrap complete. Correct: keep these planned conventions and wait for HOSTSEC-34.
