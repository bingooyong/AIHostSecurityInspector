# HostSec Go engineering specification

Package: backend (backend/); layer: go. Read the real module and task artifacts before changing code. Layout is enforced by the repository scripts; planned capabilities are not current implementation.

## Pre-Development Checklist

- [Directory and module contracts](directory-structure.md): required for every Go/build/CI/path change.
- [Quality and tests](quality-guidelines.md), [errors](error-handling.md), [logging](logging-guidelines.md): required for runtime changes.
- [Database](database-guidelines.md): storage work only; no database exists in the offline slice.
- Load task prd/design/implement and every relevant JSONL source. Read docs/03-sdd/CLI-SDD.md for current CLI behavior; REPOSITORY-LAYOUT and ADR-008 own monorepo structure.

## Quality Check

From the repository root run make test/vet/lint/boundaries/layout/baseline/check. Direct module checks use go -C backend test -race -count=1 ./..., go -C backend vet ./..., go -C backend mod verify. Log command cwd and exact exits. Root go test ./... is not the project entry point. No arbitrary shell surface, SSH trust bypass, automatic remediation or raw sensitive model input.

## Existing examples

- backend/internal/asset/asset.go: bounded loading, exact YAML/JSON types, authorization metadata; tests alongside.
- backend/internal/planner/planner.go: all-or-nothing target selection and explicitly nonexecutable offline plans.
- backend/internal/cli/cli.go: flags, structured stderr/JSON stdout, unavailable doctor.
- backend/tools/check-boundaries/main.go and scripts/check_layout.py: runtime/import and repository/module boundaries.
- scripts/verify.py: records gates/cwd/exits under current evidence directory; does not rewrite bootstrap evidence.

Collector/Rule/Analyzer extension tests now exist as PARTIAL local/fixture coverage. Linux runtime acceptance, SSH, platform identity, and hosted frontend E2E remain unverified.
