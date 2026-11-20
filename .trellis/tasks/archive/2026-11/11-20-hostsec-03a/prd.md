# HOSTSEC-03A — Offline authorized planning slice

## Goal
Deliver a runnable CLI proving that an authorized asset can be parsed and turned into an explicit read-only offline plan. This is the first MVP-1 slice, not a scanner.

## Requirements
- Commands/version/help/doctor/assets validate/list/plan as defined in CLI-SDD.
- YAML and JSON assets, strict schema/relational checks, explicit host authorization and per-profile allowlist.
- Four built-in profiles with resource/approval information; no connection or execution.
- Machine-readable output, bounded untrusted input and safe diagnostics.
- No production connection, arbitrary shell, AI call or state-changing host action.

## Acceptance
CLI builds and runs; sample assets validate; pilot plan is schema-valid. Unregistered/unauthorized host, mixed unauthorized group, invalid Profile, host key bypass, injection flags and malformed/bounded config fail nonzero. Deep/IR planning indicates approval and execution_ready=false. Darwin doctor explicitly reports Linux collector unavailable. Fresh tests, vet, lint and Linux dual-arch builds are recorded.

## Out of scope
Scan, SQLite/history, transport, collectors, rules, evidence persistence, approval verification, AI, tool integration and MCP remain planned. No unresolved question blocks this offline slice.
