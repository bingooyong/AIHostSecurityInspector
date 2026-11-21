# HOSTSEC box-lab matrix (2026-11-21)

Scope: isolated Grok Bot box (Debian GNU/Linux 13 trixie, x86_64) used as an authorized loopback lab. Collection is of this machine only, via local root or OpenSSH on `127.0.0.1:2222`. Not enterprise scanning, not a platform IdP, not production mTLS, not dual-architecture MVP acceptance.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 14 / PARTIAL 33 / BLOCKED 1 / PLANNED 0**.

Doctor JSON remains frozen (`collector_available=false`, `scan_ready=false`, exit 1, 11-case CLI contract unchanged). `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. Product flags on lab inspect results stay false.

## Moved to IMPLEMENTED

| ID | Title | What landed | Why IMPLEMENTED is honest |
| --- | --- | --- | --- |
| HOSTSEC-08 | Linux身份与系统采集 | Live `/` collection on this Debian 13 host: distro, kernel, resources, boot, hashed machine/boot identity, timeout handling. | Acceptance is met by live evidence, not only fixtures. Single x86_64 host, not a distro matrix. |
| HOSTSEC-09 | Linux进程采集 | Live process inventory (PID/PPID/UID/path/start/hash); permission and missing exe recorded as warnings, not as success. | Live records exist; unread processes stay partial. |
| HOSTSEC-10 | Linux本机网络采集 | Live listeners/connections/routes/DNS/firewall view; no network probing. | Collected from this host's `/proc` and local files only. |
| HOSTSEC-11 | Linux账号权限采集 | Live users/groups/sudo/authorized_keys fingerprints. Private keys are not read. | Live inventory plus key-material tests. |
| HOSTSEC-12 | 服务与持久化采集 | Live systemd/timer/cron/profile/module collection; unread files are warnings. | Ran on this host; some root-only files remain partial. |
| HOSTSEC-13 | 安全配置采集 | Live SSH/sudo/PAM/audit/LSMs/firewall status. Missing files are not treated as compliant. | Live partial/success with explicit warnings. |
| HOSTSEC-14 | SSH固定Collector Transport | Strict known_hosts, dedicated `hostsec-lab` user (non-root), forced `hostsec-collector` command, no arbitrary exec. Real OpenSSH to `127.0.0.1:2222` plus in-process mismatch/cancel/timeout tests. | Loopback lab only. Not a fleet transport. |
| HOSTSEC-15 | 本地SQLite和证据落盘 | Durable SQLite (WAL, 0700/0600), append-only evidence and audit, checksummed migrations, recover-on-open, reopen tests. Lab inspect wrote real `hostsec.sqlite` files. | Local store, not a hosted evidence service. |
| HOSTSEC-37 | 受限文件元数据采集 | Live targeted file metadata (124 records) with existing symlink/escape tests kept. | Not a full-disk scan. |
| HOSTSEC-38 | 软件包清单 | Live dpkg inventory, 757 packages, no installs/upgrades by the collector. | Debian only on this host; no RPM host. |

## Tightened this round (still PARTIAL)

| ID | Title | What landed | Why still PARTIAL |
| --- | --- | --- | --- |
| HOSTSEC-31 | 区域Runner | In-process lab mTLS (local CA, TLS 1.3, loopback only) plus nonce expiry/replay tests. Existing signed-task runner unchanged. | Not a regional production runner, not two isolated zones, not production trust material. |
| HOSTSEC-32 | 平台审批与审计 | Audit events can persist in SQLite and survive reopen; API can attach a durable DB when `--out` is set. | Still not a platform approval service; no IdP. |
| HOSTSEC-36 | 调度状态机与端到端扫描 | `RunAuthorized` plus `inspect-local` on an authorized loopback host. Cancel/timeout/failed fixture never become `COMPLETED`/`PASS`. Failed collection cannot stay a rule PASS when evidence is missing. | Resource-pressure stop is not executed. Not a production scheduler. |
| HOSTSEC-40 | 统一只读工具执行器 | Still the readonly stub. | osquery is not in Debian trixie. lynis/OpenSCAP/ClamAV/YARA are in the archive but were not installed this round, so adapters stay honest `not_available`. |

## Unchanged BLOCKED

| ID | Reason |
| --- | --- |
| HOSTSEC-43 | Requires MVP1-6 with AC01-15 evidence and Linux dual-architecture runtime. This box is x86_64 only. Live loopback evidence is not that acceptance. |

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`. `hostsec scan` and `mcp serve` remain rejected. Lab commands are `inspect-local` and the deployed `hostsec-collector` agent. Unauthorized hosts, non-loopback addresses, and unpinned known_hosts are still rejected.
