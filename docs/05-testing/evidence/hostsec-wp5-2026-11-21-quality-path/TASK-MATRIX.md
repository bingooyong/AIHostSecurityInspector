# HOSTSEC quality-path matrix (2026-11-21)

Scope: isolated Grok Bot box (Debian GNU/Linux 13 trixie, x86_64) and offline fixtures. This round first fixed PR 6 CI, then closed foundational Trellis nodes that can be honestly completed here. Not enterprise IdP, not regional production mTLS, not dual-architecture MVP acceptance.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 23 / PARTIAL 24 / BLOCKED 1 / PLANNED 0**.

Doctor JSON remains frozen (`collector_available=false`, `scan_ready=false`, exit 1, 11-case CLI contract unchanged). `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`.

## CI fix (pushed first)

Head `47e07c17cd62a1bf907f08cd7f753e04642344a8`. Root cause: `TestLiveLinuxCollectorsReadThisHost` required the substring `linux` in the raw identity JSON. The collector is correct — `os` is the os-release `ID` and `distribution` is `NAME`. That passed on Debian (`NAME=Debian GNU/Linux`) and failed on Ubuntu GitHub runners (`ID=ubuntu`, `NAME=Ubuntu`). The test also scanned the runner root during default `make check`.

Fix: structured identity field assertions; Ubuntu os-release fixture; live-root collection gated by `HOSTSEC_LIVE_LINUX=1`; `TestLiveRootStillRejectedWithoutLiveFlag` stays always-on. Local `make check` 23/23 PASS in `docs/05-testing/evidence/hostsec-wp5-2026-11-21-ci-fix`. Remote CI PASS: https://github.com/bingooyong/AIHostSecurityInspector/actions/runs/44882655178 (job `offline-cli`). PR https://github.com/bingooyong/AIHostSecurityInspector/pull/6 was not merged.

## Moved to IMPLEMENTED

| ID | Title | What landed | Why IMPLEMENTED is honest |
| --- | --- | --- | --- |
| HOSTSEC-03 | Go 工程构建与发布骨架 | Version injection, amd64/arm64 ELF checks, two-directory reproducible amd64 hash, manifest with schema_version/source_commit/source_tree_hash/dirty/build flags, invalid VERSION cannot write a success manifest, native `version --json` matches the injected version. | Platform matrix is a cross-build, labeled `CROSS_BUILD_ONLY`. Compile is not runtime acceptance. HOSTSEC-43 stays BLOCKED. |
| HOSTSEC-04 | 完整领域模型与版本化Schema | Existing domain/schema tests plus the report producer now emits `scan-result-v1` required fields. Snapshot tests still reject cross-scope and unusable evidence. | Model/schema work is complete. It is not a live dual-arch scan. |
| HOSTSEC-05 | CLI生命周期与输出契约 | Existing JSON/exit/timeout flag tests plus real-process SIGINT/SIGTERM and `--timeout-seconds` against a blocked loopback API. Cancel/deadline exit 1 with `CANCELLED`. | Frozen 11-case doctor contract unchanged. `hostsec scan` still rejected. |
| HOSTSEC-06 | 资产授权和治理 | YAML/JSON inventories, atomic authorization, snapshot hashes, and security-field diffs already tested. | Inventory/authorization kernel is complete. Not a fleet CMDB. |
| HOSTSEC-16 | SHA256 Manifest完整性 | Dual digests; missing raw is not forged; tamper, missing object, corrupt manifest, cross-scan, and replayed manifest fail verify. Corrupt files are not rebuilt into a passing report. | Hash integrity is not source authenticity (`source_authenticity=unverified`). |
| HOSTSEC-18 | Finding与RuleResult模型 | FAIL with usable same-host/same-scan evidence creates findings. PASS/UNKNOWN/N/A do not. Cross-host/scan and unverified evidence are rejected. | Four-state model is complete. Not an enterprise pipeline. |
| HOSTSEC-17 | 有限DSL YAML规则引擎 | Nine MVP rules with `required_evidence` and PASS/FAIL/UNKNOWN/N/A. Unknown predicates are rejected, so the engine does not execute code. | Rule-bundle signing is a supply-chain hook, not this node's AC. |
| HOSTSEC-19 | JSON Markdown报告 | Reports include the 17 scan-result fields, coverage denominator, uncovered modules, human review, and evidence index. Incomplete scans stay PARTIAL and must not look secure. AI failure still yields a deterministic report. Malicious Markdown is neutralized. | Depends on inspect/lab paths; HOSTSEC-36 remains PARTIAL. Incomplete scans do not look like a secure host. |
| HOSTSEC-42 | CI与供应链门禁 | format/vet/lint/race/integration/schema/frontend/security/vuln/SBOM/dual-arch digest gates. | Local and remote recorded separately. Remote PASS observed for `47e07c1` at the run linked above. Later commits need their own remote result; do not assume it. |

## Stayed PARTIAL (honestly)

| ID | Title | Why still PARTIAL |
| --- | --- | --- |
| HOSTSEC-32A | 本地审批与审计前置 | Local verifier/ledger/journal tests already reject forged, expired, replay, and self-approval, but planned deliverable paths `approval/local.go`, `audit/local.go`, and their testdata directories do not exist, so this node stays PARTIAL rather than inventing placeholder files. Not HOSTSEC-32. |
| HOSTSEC-07 | 可执行计划与策略约束 | Four profiles and preflight/approval binding exist, but `schemas/policy-v1.schema.json` and `policies/` are still missing, and resource-pressure as a live preflight input is not fully executed. |
| HOSTSEC-44 | 可信基线与扫描差异 | First scan is a candidate snapshot and rules can consume a trusted fixture, but approved-baseline workflow, historical attempts, and baseline-tamper/drift acceptance are not complete. |
| HOSTSEC-39 | 离线漏洞情报关联 | Missing catalog is UNKNOWN. No versioned distro/epoch/backport intel library was added this round. |
| HOSTSEC-41 | 离线结果包与来源验证 | Symlink escape is rejected. Restricted tar.zst unpack, source identity, and import transactions are not complete. |
| HOSTSEC-40 | 统一只读工具执行器 | Readonly stub still reports `not_available`. No adapter was wired to a real lynis/OpenSCAP/ClamAV/YARA process this round; osquery is not in Debian trixie. |
| HOSTSEC-45 | 身份与区域RBAC | File-based local identities, zone filter, auditor read-only, agent inherit, and revoke exist. No platform IdP or session cache. HOSTSEC-32 remains PARTIAL. |
| HOSTSEC-31 / 32 / 36 | runner / platform approval / scheduler | Tightened earlier as lab slices. Still not a regional production runner, platform IdP, or production scheduler. Resource-pressure stop is not executed for 36. |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | Requires MVP1-6 with AC01-15 evidence and Linux dual-architecture runtime. This box is x86_64 only. Live loopback evidence is not that acceptance. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`. `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`.

## Quality gates

Local `HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp5-2026-11-21-quality-path make check`: **23/23 PASS** (Taipei time, 2026-11-21). See `results.json` in this directory. This local run is not a remote CI result.

Remote CI already observed PASS for the earlier CI-fix commit `47e07c17cd62a1bf907f08cd7f753e04642344a8`: https://github.com/bingooyong/AIHostSecurityInspector/actions/runs/44882655178. Remote CI for the Trellis follow-up commit is recorded only after that Actions run finishes; do not assume it passed.
