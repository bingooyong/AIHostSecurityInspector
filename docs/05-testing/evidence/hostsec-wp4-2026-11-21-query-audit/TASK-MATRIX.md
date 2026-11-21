# HOSTSEC query-audit matrix (2026-11-21)

Scope: isolated development only. Fixture collectors, local identities, loopback API, Playwright. Not enterprise scanning, IdP, mTLS, or production hosting.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 4 / PARTIAL 43 / BLOCKED 1 / PLANNED 0**.

No DAG node moved to IMPLEMENTED. HOSTSEC-43 stays BLOCKED. Doctor JSON remains frozen (`collector_available=false`, exit 1).

## Tightened this round (still PARTIAL)

| ID | Title | What landed | Why still PARTIAL |
| --- | --- | --- | --- |
| HOSTSEC-13 | 安全配置采集 | sshd `Include` is followed inside the fixture root (glob, last-wins, depth/file caps, `..` escape rejected). `sudoers.d` files are read via the existing `listDir` paths instead of double-prefixed misses. | No live distro/VM matrix. Missing config is still not treated as compliant. |
| HOSTSEC-32 | 平台审批与审计 | `Workflow.List`; local in-memory audit events on plan/request/run; `GET /v1/approvals` is zone-filtered; `GET /v1/audit` is auditor-only. | Not a platform approval service, no durable audit store, no IdP. |
| HOSTSEC-33 | Go Web API | `GET /v1/scans/{id}/evidence` with IDOR; rate-limit returns `RATE_LIMITED`/429; cancelled request context returns `CANCELLED`/408. | Loopback header identity ≠ OIDC/mTLS/production. |
| HOSTSEC-34 | React TS管理端 | Console fetches real evidence metadata and approval pages instead of fabricating `integrity_status=unknown`. Playwright hits evidence IDOR and auditor-only audit. | Loopback Playwright ≠ hosted API or platform identity. |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | No authorized enterprise VM/SSH/production window. Isolation forbids real hosts. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`, `execution_ready=false`. `hostsec scan` and `mcp serve` remain rejected. Doctor stdout is still the frozen 11-case CLI contract.
