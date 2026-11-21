# HOSTSEC tool-lab matrix (2026-11-21)

Scope: isolated Grok Bot box (Debian GNU/Linux 13 trixie, x86_64) plus two authorized amd64 chroots created on this box. Official vendor packages were installed and executed behind `HOSTSEC_LIVE_TOOLS=1`. This is not enterprise IdP, not regional production mTLS, not a 3–5 host dual-architecture MVP, and not a QEMU/VM matrix.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 36 / PARTIAL 11 / BLOCKED 1 / PLANNED 0**. No Trellis node was promoted or demoted in this round.

Doctor JSON remains frozen (`collector_available=false`, `scan_ready=false`, exit 1, 11-case CLI contract unchanged). `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. HOSTSEC-43 stays BLOCKED. Default `make check` / CI do not install vendor packs, do not set `HOSTSEC_LIVE_TOOLS` or `HOSTSEC_LIVE_LINUX`, and do not audit the live runner.

## What was installed on this lab box

Sources and versions are recorded in `installed-versions.txt`.

| Tool | Package | Version | Notes |
| --- | --- | --- | --- |
| osquery | official `osquery_5.24.1-1.linux_amd64.deb` (GitHub release 5.24.1, sha256 `c6a37aec1156712cce0fafeb01a3697a2b73a1863a2b39fc3473b07600aea68d`) | 5.24.1-1.linux | `osqueryi` only; `osqueryd` was not started. Debian trixie still has no osquery package. |
| Lynis | Debian `lynis` | 3.1.4-1 | Official Debian package, not upstream 3.1.7. Binary is `/usr/sbin/lynis`. The package timer symlink was removed; systemd is not PID 1 on this box. |
| OpenSCAP | Debian `openscap-scanner` + `openscap-utils` | 1.4.2+dfsg-1 | Official Debian package, not upstream 1.4.6. |
| SCAP Security Guide | Debian `ssg-debian`, `ssg-debderived`, `ssg-nondebian`, `ssg-base` | 0.1.76-1 | Official content for debian11/12 and ubuntu16.04–24.04. **No debian13 datastream.** |
| ClamAV | Debian `clamav` + `clamav-freshclam` | 1.4.6+dfsg-1~deb13u1 | Official Debian package, not upstream 1.5.5. `clamd` was not installed. Official CVD signatures were fetched once with `freshclam` (daily 28190, main 63, bytecode 339). |
| YARA | Debian `yara` | 4.5.2-1 | Official Debian package, not upstream 4.6.0. YARA-X was not substituted. |
| mmdebstrap / ubuntu-keyring | Debian packages | 1.5.7-1+deb13u1 / 2023.11.28.1-0.2 | Used only to create authorized lab chroots. Docker, Podman, and QEMU were not installed. |

## What actually ran

Live adapter tests (`HOSTSEC_LIVE_TOOLS=1 go test`, default CI flag unset) are summarized in `live-tests.redacted.json`: 15 pass, 0 fail, 1 skip (`TestLiveOpenSCAPChrootMatrix` skipped unless a chroot path is provided). Host identity was redacted from committed logs.

| Adapter | Demonstration | Side effects |
| --- | --- | --- |
| osquery | Fixed query IDs `osquery_info`, `os_version`, `platform_info`. Caller SQL, meta commands, and `--extension` are rejected. Fixture coverage for missing tool, timeout, corrupt JSON, and output limit. Live `osqueryi --disable_extensions --json` on this Debian 13 host, pinned 5.24.1, platform linux. Raw rows are not retained on the result. | Read-only queries; no daemon. |
| Lynis | Adapter now uses official `--report-file` / `--logfile` (Debian 3.1.4 has no `--report-dir`). Writes are forced into a controlled directory; `HOME` was set to that directory in the live test so pid/log fallbacks cannot escape. Approved test `BOOT-5104` only, with a lab profile copy that sets `refresh-repositories=no`. Fixture coverage remains. | AC-12 style before/after snapshot of the report dir (`lynis-report.dat`, `lynis.log`). No raw report is committed. |
| OpenSCAP | Adapter refuses debian-13 vs debian-12 content, including a debian-12 datastream relabeled as debian-13. `--remediate` and `--fetch-remote-resources` stay forbidden. Official `oscap-chroot` (root) evaluated one rule each on Debian 12 and Ubuntu 24.04 chroots with OS-matched official SSG. Unprivileged `oscap-chroot` from the Go test is not claimed as a successful eval (it cannot enter the chroot). | Results XML was hashed then deleted; not committed. Chroot `/etc` file counts were unchanged. Remote OVAL references were skipped, not fetched. |
| ClamAV | Default binary is now `clamscan` (no daemon). Live scan of a synthetic EICAR file and a clean file in a temp approved root only, using `/var/lib/clamav`. `/etc/passwd` stays rejected. Exit 1 is a detection, not a crash. | AC-12 snapshot of the EICAR file: content and path unchanged (no remove/move/copy). |
| YARA | Reviewed pack `backend/internal/tools/yara/rules/hostsec_harmless.yar`. Live official `yara --timeout=SECONDS` hit/clean/scope tests. Include directives and external variables still rejected. | Scoped to the temp target; no host-wide scan. |

Limited distro matrix (amd64 chroots only) is in `matrix/`:

- Debian 12 bookworm chroot: `xccdf_org.ssgproject.content_rule_prefer_64bit_os` → pass, exit 0.
- Ubuntu 24.04 noble chroot: `xccdf_org.ssgproject.content_rule_package_prelink_removed` → pass, exit 0.

This box itself is Debian 13 and has no official SSG stream, so the runner host was not OpenSCAP-evaluated.

## Stayed PARTIAL (honestly)

| ID | Title | Exact remaining gap |
| --- | --- | --- |
| HOSTSEC-20 | Osquery Adapter | Fixed-query adapter, fixtures, and a real official `osqueryi` 5.24.1 run on this amd64 Debian 13 host are done. The automated test requirement still names a real test VM, and there is no dual-arch / multi-host matrix. |
| HOSTSEC-21 | Lynis Adapter | Official Debian Lynis 3.1.4 ran with a controlled report dir, approved test list, and side-effect snapshot on this one host. That is not a distro/VM matrix, and the package is not the upstream 3.1.7 observation in TOOL-EVALUATION.md. |
| HOSTSEC-22 | OpenSCAP Adapter | Official scanner + OS-matched SSG were proven on Debian 12 and Ubuntu 24.04 amd64 chroots, and debian-13 mismatch/fetch/remediate guards were tested. This is still not a VM matrix, there is no debian-13 content, no ARM64 run, and unprivileged `oscap-chroot` cannot be claimed as a completed eval. |
| HOSTSEC-23 | ClamAV Adapter | Official `clamscan` + fresh signatures scanned only approved synthetic paths on this host. Not a distro/VM matrix; `clamd` was not used; package is not upstream 1.5.5. |
| HOSTSEC-24 | YARA Adapter | Official YARA 4.5.2 ran the reviewed pack with scope and timeout on this host. Not a distro/VM matrix; not YARA-X; package is not upstream 4.6.0. |
| HOSTSEC-30 | MCP标准业务工具 | Unchanged: ten stdio tools exist, `mcp serve` stays rejected, caller identity is local. |
| HOSTSEC-33 | Go Web API | Unchanged: loopback API tests exist, not a completed authorized application service. |
| HOSTSEC-34 | React TS管理端 | Unchanged: pages and frontend gates exist, not a completed operations center. |
| HOSTSEC-45 / 31 / 32 | RBAC / 区域Runner / 平台审批 | Unchanged: no platform IdP/SSO and no regional production mTLS runner. |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | Requires MVP1-6 with AC01-15 and Linux dual-architecture runtime. This box and the new chroots are x86_64 only. Cross-compile, one amd64 host, or amd64 chroots are not that acceptance. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`. `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. CI concurrency and triggers in `.github/workflows/ci.yml` were not changed. The archived cloud agent was not launched or unarchived. This PR is not merged.

## Quality gates

Local `PATH="/tmp/hostsec-venv/bin:$PATH" HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp5-2026-11-21-tool-lab make check` (no `HOSTSEC_LIVE_LINUX` / `HOSTSEC_LIVE_SSH` / `HOSTSEC_LIVE_TOOLS`): **23/23 PASS** (Asia/Taipei, 2026-11-21 20:57 CST). See `results.json` in this directory. This local run is not a remote CI result. Frozen doctor flags were rechecked on the local binary: `collector_available=false`, `scan_ready=false`, exit 1; `hostsec scan` and `mcp serve` stay rejected.

Remote CI for the pushed head will be recorded only after the GitHub Actions run concludes. PR https://github.com/bingooyong/AIHostSecurityInspector/pull/6 is not merged.
