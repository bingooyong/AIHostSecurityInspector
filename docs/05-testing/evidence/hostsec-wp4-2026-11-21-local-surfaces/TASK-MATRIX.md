# HOSTSEC local-surfaces matrix (2026-11-21)

Scope: isolated development only. Fixture inspect, local identities, stdio MCP, loopback API, in-process runner, local frontend. Not enterprise scanning.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 4 / PARTIAL 43 / BLOCKED 1 / PLANNED 0**.

## Changed this round (BLOCKED → PARTIAL)

| ID | Title | Why PARTIAL, not IMPLEMENTED | Evidence |
| --- | --- | --- | --- |
| HOSTSEC-45 | 身份与区域RBAC | File-based local identities, zone/business filter, auditor read-only, agent inherit, revoke. No platform IdP, session cache, or enterprise SSO. | `backend/internal/authorization/identity.go`, `identity_test.go`, `examples/identities.json` |
| HOSTSEC-32 | 平台审批与审计 | Request≠grant, self-approve rejected, preflight consume uses journal+ledger. Not a platform approval service. | `backend/internal/approval/workflow.go`, `backend/internal/planner/consume_test.go` |
| HOSTSEC-30 | MCP标准业务工具 | JSON-RPC stdio implements the 10 tools and rejects forbidden tools/self-asserted roles. No official MCP SDK, no authenticated HTTP MCP. | `backend/internal/mcp/server.go`, `server_test.go`, `hostsec mcp stdio` |
| HOSTSEC-31 | 区域Runner | Signed task, zone match, expiry, nonce replay, fixture inspect only. mTLS and real regional isolation UNVERIFIED. | `backend/internal/runner/runner.go`, `runner_test.go` |
| HOSTSEC-33 | Go Web API | httptest + loopback-only listen, header identity, IDOR/rate-limit/self-asserted role tests. No OIDC/mTLS/production bind. | `backend/internal/api/handler.go`, `handler_test.go`, `hostsec api` |
| HOSTSEC-34 | React TS管理端 | Real package with lockfile, lint/typecheck/vitest/build, empty/error/403/XSS/PARTIAL states. No Playwright live-API E2E. | `frontend/` |
| HOSTSEC-35 | 风险整改与趋势 | False-positive/remediation/rescan links; first scan cannot report change; no auto-remediation. No production closed-loop. | `backend/internal/risk/risk.go`, `risk_test.go` |

## Supporting PARTIAL upgrades (already PARTIAL)

| ID | Change |
| --- | --- |
| HOSTSEC-16 | Manifest/rule-bundle ed25519 signing hooks; signature ≠ host authenticity |
| HOSTSEC-32A | Preflight `--consume` now requires journal + nonce ledger |
| HOSTSEC-36 | Job state machine; fixture inspect ends PARTIAL, cannot skip to COMPLETED |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | No authorized enterprise VM/SSH/production window. Isolation forbids real hosts. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`, `execution_ready=false`, `limits.enforced=false`. Fixture/MCP/API/runner tests assert they stay false.
