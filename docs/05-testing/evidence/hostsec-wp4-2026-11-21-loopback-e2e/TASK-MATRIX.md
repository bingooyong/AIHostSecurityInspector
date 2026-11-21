# HOSTSEC loopback-e2e matrix (2026-11-21)

Scope: isolated development only. Fixture inspect, local identities, stdio MCP, loopback API, Playwright against that API. Not enterprise scanning, IdP, mTLS, or production hosting.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 4 / PARTIAL 43 / BLOCKED 1 / PLANNED 0**.

No DAG node moved to IMPLEMENTED. HOSTSEC-43 stays BLOCKED.

## Tightened this round (still PARTIAL)

| ID | Title | What landed | Why still PARTIAL |
| --- | --- | --- | --- |
| HOSTSEC-30 | MCP标准业务工具 | stdio JSON-RPC requires `initialize` (`protocolVersion` + `clientInfo.name`, extra fields rejected); `tools/list` cursor pagination; `list_authorized_hosts`/`list_findings` limit/offset (max 100); `run_host_scan` idempotency returns the stored job without re-inspect. Still rejects `execute_shell`/`ssh_exec` and self-asserted roles. | Not official MCP SDK. Not HTTP MCP with platform identity. |
| HOSTSEC-33 | Go Web API | `GET /healthz`, `GET /v1/scans` list, pagination query, loopback-only CORS, public host DTO (no `auth_ref`), scan-list IDOR filter. httptest + Playwright hit the real handler. | No OIDC/mTLS/production bind. Local header identity is not a platform IdP. |
| HOSTSEC-34 | React TS管理端 | Console fetches paginated `/v1/hosts` and `/v1/scans` with `X-HostSec-Principal` from `?principal=`. Playwright Chromium drives the built UI against `hostsec api` on `127.0.0.1`. | Loopback Playwright ≠ hosted API, platform identity, or enterprise UI acceptance. |
| HOSTSEC-36 | 任务编排与状态机 | `JobStore.LookupByKey` / `List`; `RunHostScan` returns the stored result on idempotent replay instead of advancing again. | In-memory fixture jobs only. Not a production orchestrator. |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | No authorized enterprise VM/SSH/production window. Isolation forbids real hosts. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`, `execution_ready=false`, `limits.enforced=false`. Fixture/MCP/API/Playwright tests assert they stay false. `hostsec scan` and `mcp serve` remain rejected.
