# HOSTSEC lab-surfaces matrix (2026-11-21)

Scope: isolated Grok Bot box (Debian GNU/Linux 13 trixie, x86_64) and offline fixtures. This round continued the quality-first Trellis path on open PR 6. Not enterprise IdP, not regional production mTLS, not a production scheduler, not dual-architecture MVP acceptance.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 36 / PARTIAL 11 / BLOCKED 1 / PLANNED 0**.

Doctor JSON remains frozen (`collector_available=false`, `scan_ready=false`, exit 1, 11-case CLI contract unchanged). `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. HOSTSEC-43 stays BLOCKED. Live root inspect tests are now gated by `HOSTSEC_LIVE_LINUX=1` so default `make check` / CI do not collect live `/`.

## Moved to IMPLEMENTED

| ID | Title | What landed | Why IMPLEMENTED is honest |
| --- | --- | --- | --- |
| HOSTSEC-36 | 调度状态机与端到端扫描 | Lab scheduler now rechecks plan/authorization (asset snapshot and policy hash) before collect, isolates modules with per-module timeout, executes a resource-pressure stop (PSI parser plus injectable source), honours cancel, and downgrades any rule PASS when collection failed, timed out, cancelled, or stopped for pressure. Fixture tests actually run this path. Live `/` inspect tests are env-gated. | AC (module timeout/cancel/pressure-stop/limits, plan-authorization recheck, failure is not PASS) is met on fixtures. This is a local/lab state machine, not a production/fleet scheduler. |
| HOSTSEC-35 | 风险整改与趋势 | Persistent cases link false-positive, human remediation, and rescan. Auto/train actors are rejected. A rescan cannot verify a case before remediation. Same-host absence verifies; a later hit reopens; host identity drift cannot close a case. Time series history and multi-scan Series diffs are tested. | 误报/整改/复扫关联, 不自动训练或处置, plus 时间序列/主机身份漂移/闭环状态 tests are met in `backend/internal/risk/`. This is not a frontend operations console (HOSTSEC-34 stays PARTIAL). |
| HOSTSEC-25 | AI Provider抽象 | `backend/internal/analyzer/provider/` is disabled by default. OpenAI-compatible/local clients share timeout, request/response byte limits, host allowlisting, and no-redirect SSRF control. httptest covers timeout, 429, 5xx, and oversized responses with no real outbound network. | AC and listed tests are met. No production model endpoint is configured. |
| HOSTSEC-26 | AI最小脱敏视图 | `backend/internal/analyzer/redaction/` allowlists fields, redacts credentials, connection strings, private keys, SSH keys, and email, applies a length cap, and fail-closes outbound if a secret remains. | Planted-secret and fail-closed tests are met. Default path stays local. |
| HOSTSEC-27 | 结构化AI关联研判 | `analysis.go` requires the 11 judgment fields, keeps facts and inferences separate, refuses severity/finding overrides, rejects injection-like text, and degrades invalid JSON/enum/timeout/no-model to AI failed while preserving deterministic findings and rule severity. | AC is met with tests. AI stays disabled unless an allowlisted test endpoint is supplied. |
| HOSTSEC-28 | AI证据引用验证 | `validate.go` requires same scan/host and only evidence IDs in the minimized allow-list. Fictional IDs, cross-host, cross-scan, empty, and polluted refs are rejected. | AC and listed negative tests are met. |
| HOSTSEC-29 | Codex Claude Skill接入 | Planned deliverables `integrations/skills/host-security-inspection/SKILL.md` and `integrations/README.md` exist. The skill may call only implemented CLI (assets/plan/intent/preflight/inspect-fixture). It forbids shell, `execute_shell`, `ssh_exec`, `hostsec scan`, and `mcp serve`, and it rejects live `/`. A contract test reads the skill file. | AC (only implemented CLI, auth/plan/report flow, no arbitrary shell) is met as a skill contract. The skill does not enable live scan or AI. |

## Stayed PARTIAL (honestly)

| ID | Title | Exact remaining gap |
| --- | --- | --- |
| HOSTSEC-20 | Osquery Adapter | osquery is not in Debian trixie and was not installed. Fixed-query/version/platform adapter work was not claimed complete. |
| HOSTSEC-21 / 22 / 23 / 24 | Lynis / OpenSCAP / ClamAV / YARA | Real adapter packages and fixture tests now exist (controlled report dir and side-effect disclosure; OS-matched content and no remediate/fetch; approved paths, signature freshness, EICAR vs error exit, no mutate; reviewed rules, scope, timeout, rejected include/external vars). Default `make check` does not audit the live host. These stay PARTIAL because the vendor packages, real SCAP content packs, and signature libraries were not installed or executed, and there is no distro/VM matrix. |
| HOSTSEC-30 | MCP标准业务工具 | Ten stdio tools and forbidden-tool rejection already exist. `mcp serve` stays rejected. Caller identity is local, not platform approval/RBAC (HOSTSEC-32 / 45). |
| HOSTSEC-33 | Go Web API | Loopback API already has RBAC/IDOR/rate-limit/cancel tests, but depends on unfinished MCP/runner/platform approval/RBAC and is not a completed authorized application service for detection jobs. |
| HOSTSEC-34 | React TS管理端 | Pages exist for assets/jobs/evidence/rules/approvals and frontend CI gates remain, but this is not a completed, authorized operations center over a finished API. |
| HOSTSEC-45 / 31 / 32 | RBAC / 区域Runner / 平台审批 | Local identities and earlier lab slices only. No platform IdP/SSO/secrets and no regional production mTLS runner. |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | Requires MVP1-6 with AC01-15 and Linux dual-architecture runtime. This box is x86_64 only. Cross-compile or single-arch loopback is not that acceptance. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`. `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. CI concurrency and triggers in `.github/workflows/ci.yml` were not changed.

## Quality gates

Local `PATH="/tmp/hostsec-venv/bin:$PATH" HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp5-2026-11-21-lab-surfaces make check` (no `HOSTSEC_LIVE_LINUX` / `HOSTSEC_LIVE_SSH`): **23/23 PASS** (Asia/Taipei, 2026-11-21). See `results.json` in this directory. This local run is not a remote CI result.

Remote CI for this head will be recorded only after the GitHub Actions run for the pushed commit concludes. PR https://github.com/bingooyong/AIHostSecurityInspector/pull/6 is not merged.
