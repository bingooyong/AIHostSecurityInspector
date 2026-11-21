# HOSTSEC closable-gaps matrix (2026-11-21)

Scope: isolated Grok Bot box (Debian GNU/Linux 13 trixie, x86_64) and offline fixtures. This round continued the quality-first Trellis path on open PR 6, closing remaining PARTIAL nodes whose acceptance can be met here. Not enterprise IdP, not regional production mTLS, not a production scheduler, not dual-architecture MVP acceptance.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 29 / PARTIAL 18 / BLOCKED 1 / PLANNED 0**.

Doctor JSON remains frozen (`collector_available=false`, `scan_ready=false`, exit 1, 11-case CLI contract unchanged). `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. HOSTSEC-43 stays BLOCKED.

## Moved to IMPLEMENTED

| ID | Title | What landed | Why IMPLEMENTED is honest |
| --- | --- | --- | --- |
| HOSTSEC-32A | 本地审批与审计前置 | Added the planned deliverables `approval/local.go` and `audit/local.go`, plus `approval/testdata/` and `audit/testdata/`. Local verifier loads the fixture trust store and signed approval, consumes a nonce once, and rejects tampered, revoked, cross-target, expired, and replayed documents. Local audit records allow then consume, and rejects writes to a truncated journal. Approval still does not import audit. | AC for no-approval, forged, expired, replay, cross-target, and plan-drift rejection is met with file-backed local APIs and fixture tests. This is not HOSTSEC-32 platform approval/IdP. |
| HOSTSEC-07 | 可执行计划与策略约束 | Added versioned `schemas/policy-v1.schema.json` and `policies/builtin-v1.json` matching the four builtin profiles. `policy.Load` rejects unknown/unsafe modules and tools, negative limits, `enforced=true`, and write mode. Integration validates the builtin document against the schema. Preflight re-hashes the current policy and treats unprobed or missing capabilities as unavailable; it still cannot set `execution_ready`. | Versioned policy, plan summary, capability check, and pre-execution review exist and are tested. Live resource-pressure enforcement remains a HOSTSEC-36 concern. |
| HOSTSEC-44 | 可信基线与扫描差异 | First scan stays a candidate and is not an approved baseline. Explicit `Approve` binds a payload hash into an append-only index. `Compare` reports UNKNOWN for an unapproved snapshot, then identity, SSH key, SSH config, and service diffs after approval. History records candidate and approve attempts. Tampering the trusted file, even after recomputing its embedded hash, fails `Verify` against the index. | Approved-baseline, history, and tamper acceptance are met for local/lab scans. This is not a fleet baseline service. |
| HOSTSEC-39 | 离线漏洞情报关联 | New `backend/internal/vulnerability/` library: signed versioned catalog, Debian epoch/backport comparison, stale or unsigned catalog stays UNKNOWN, and a catalog hit with an older installed version is FAIL. A no-match is not a clean-host PASS. `intel.CorrelateCatalog` uses the library. Fixture catalog is lab-signed, not a commercial feed. | Trusted versioned intel and distro backport semantics are implemented and tested. Scope is a lab catalog library, not a production intel pipeline or vendor feed. |
| HOSTSEC-41 | 离线结果包与来源验证 | `tar.zst` pack and transactional import with signed manifest and required `source-identity.json`. Missing or tampered identity fails. Path slip is rejected. Replay of the same source nonce/scan and cross-region import are rejected. A failed import does not leave a destination tree. Compression uses `github.com/klauspost/compress/zstd` (no zstd CLI). | Restricted unpack, signature, source identity, manifest verification, and import transaction are tested. This is not a production multi-region exchange. |
| HOSTSEC-40 | 统一只读工具执行器 | Added `runner.go` and `adapter.go`. The runner allowlists binary basename and args, records version, captures exit code, enforces timeout with process-group cancel (`Setpgid` + SIGKILL), and caps output bytes. Fixture scripts cover success, timeout, output limit, and nonzero exit. Missing host tools, including ClamAV/osquery/lynis/OpenSCAP/YARA when absent, stay honest `not_available` and are not a clean scan. Default specs are `--version` only so a present binary cannot audit the live host during `make check`. `os/exec` is allowlisted only under `internal/tools/`; collectors stay exec-free. | Whitelist, version, exit code, timeout, and output-limit acceptance are met with fixtures. HOSTSEC-20..24 stay PARTIAL because those archive packages were not installed and are not claimed complete. |

## Stayed PARTIAL (honestly)

| ID | Title | Exact remaining gap |
| --- | --- | --- |
| HOSTSEC-20 / 21 / 22 / 23 / 24 | Osquery / Lynis / OpenSCAP / ClamAV / YARA adapters | Executor wiring and honest `not_available` exist, but each adapter's own AC (approved audit items, SCAP content packs, signature libraries, reviewed YARA rules, etc.) is not met because those tools were not installed and are not in Debian trixie for osquery. |
| HOSTSEC-25 / 26 / 27 / 28 / 29 | AI provider, redaction, structured judgment, evidence cite, skill | Local contracts may exist in part, but this round did not complete provider-default-disabled production wiring, a closed 11-field AI judgment path, or skill-only CLI authorization as accepted product behavior. |
| HOSTSEC-30 | MCP标准业务工具 | `mcp serve` remains rejected. Ten business tools with caller identity/permission filtering are not an accepted runtime. |
| HOSTSEC-33 | Go Web API | Loopback API exists for lifecycle tests; this is not a completed authorized, audited application service that can run detection jobs. |
| HOSTSEC-34 | React TS管理端 | Frontend gates remain in CI, but the designed operations center is not a completed, authorized management product. |
| HOSTSEC-35 | 风险整改与趋势 | Misreport / remediation / rescan correlation without auto-treatment is not delivered as an accepted workflow. |
| HOSTSEC-36 | 调度状态机与端到端扫描 | Module timeout/cancel pieces exist in places, but plan-authorization recheck plus resource-pressure stop as an executed end-to-end scheduler is not accepted. A production scheduler is not claimed. |
| HOSTSEC-45 | 身份与区域RBAC | File-based local identities and zone/auditor rules exist. Platform IdP, SSO, and session cache are missing. |
| HOSTSEC-31 / 32 | 区域Runner / 平台审批与审计 | Earlier lab slices only. Not a regional production runner with mTLS, and not platform approval/IdP/secrets. |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | Requires MVP1-6 with AC01-15 evidence and Linux dual-architecture runtime. This box is x86_64 only. Cross-compile, fixture, or single-arch loopback evidence is not that acceptance. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`. `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. CI concurrency and triggers in `.github/workflows/ci.yml` were not changed.

## Quality gates

Local `PATH="/tmp/hostsec-venv/bin:$PATH" HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp5-2026-11-21-closable-gaps make check` (no `HOSTSEC_LIVE_LINUX` / `HOSTSEC_LIVE_SSH`): **23/23 PASS** (Asia/Taipei, 2026-11-21). See `results.json` in this directory. This local run is not a remote CI result.

Remote CI for this head will be recorded only after the GitHub Actions run for the pushed commit concludes. PR https://github.com/bingooyong/AIHostSecurityInspector/pull/6 is not merged.
