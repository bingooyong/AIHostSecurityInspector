# HOSTSEC authorized-collection workflow matrix (2026-11-21)

Scope: complete the next honest slice of the authorized collection path on the same unmerged PR 7. This is still not an intranet scanner, not enterprise IdP, not regional production mTLS, and not a 3–5 host dual-architecture MVP.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 36 / PARTIAL 11 / BLOCKED 1 / PLANNED 0**. No Trellis node was promoted or demoted in this round.

Doctor JSON remains frozen (`collector_available=false`, `scan_ready=false`, exit 1, 11-case CLI contract unchanged). `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. HOSTSEC-43 stays BLOCKED. Default `make check` / CI do not start lab sshd and do not set `HOSTSEC_LIVE_SSH`, `HOSTSEC_LIVE_SSH_MULTI`, or `HOSTSEC_LIVE_TOOLS`.

## What was reviewed

The previous slice added `hostsec inspect-authorized` with allowlist, intent binding, and per-host SSH identity checks. Live two-listener collection worked, but the authorized workflow was still incomplete:

- There was no durable aggregate report under `--out`. CLI JSON was the only multi-host record, and a mid-run cancel dropped that JSON.
- Job status was always PARTIAL, including both "must not claim a production PASS" and actual incomplete modules, with no reason field.
- `inspect-authorized` accepted `--approval` / `--trust-store` but had no intent or approval consumption, so a successful intent could be replayed.
- Resource-pressure and mid-job cancel were not aggregated across hosts.
- Refusal stderr used a generic "authorized collection was rejected or failed" message.
- Official tool adapters were not invoked on this path; profile `quick` has no tools, and SSH force-command only allows `hostsec-collector`.

## Why live jobs are PARTIAL (honest)

Live collection of `linux-box-lab-ssh-001` and `linux-box-lab-ssh-002` wrote evidence and per-host reports, with evidence integrity OK. `host_identity` was `success`; the other six quick modules were `partial` because the unprivileged lab SSH users cannot read other users' `/proc/*/exe`, many systemd units, or sudoers (`exe_permission_denied`, `*_unreadable`, `permission_denied`). That incomplete module coverage is a real lab limitation, not a hidden failure and not a production PASS.

Job status remains PARTIAL for two independent reasons, now written into `job_status_reason`:

1. This authorized lab path must never return `COMPLETED` as a production completed scan.
2. In this live run, each host was `success=1 partial=6`. The aggregate reason was `allowlisted lab hosts collected=2 complete=0 incomplete=2 failed=0 cancelled=0; not a production completed scan`.

## What was implemented

- Aggregate report `authorized-collection.json` under `--out`, with host summaries, integrity flags, and no raw evidence payloads.
- Per-host and aggregate `job_status_reason` explaining PARTIAL / CANCELLED / FAILED without ever claiming `COMPLETED`.
- Mid-run cancel, deadline, and resource pressure keep already-collected hosts, mark remaining hosts as skipped, and still write the aggregate report.
- Optional `--intent-ledger` consumes the intent hash after a successful prepare and refuses replay. Approval `--journal` / `--ledger` / `--consume` are also wired, but deep/IR remain refused on this path.
- CLI refusals now surface the specific bind/prepare message (loopback-only, allowlist/intent mismatch, consumed intent) with empty stdout.
- When `HOSTSEC_LIVE_TOOLS=1`, official tool adapters run on the lab control host after authorized collection. This is a version/presence probe via the allowlisted runner, not remote tool execution over SSH, and not a dual-arch/VM tool matrix.

## How it was tested in this lab

Default unit tests (no live SSH, no `HOSTSEC_LIVE_TOOLS`) cover intent-ledger replay, pressure-before-collect report writing, job-status reasons, documentation-host CLI refusal wording, and help text for the report and intent ledger.

Live lab (Asia/Taipei, 2026-11-21 22:31–22:34 CST), loopback only:

- Two sshd listeners already bound on `127.0.0.1:2222` and `127.0.0.1:2223` only. Confirmed not bound off-loopback (`live/loopback-listen.txt`). System sshd on port 22 was not started.
- `hostsec inspect-authorized --intent-ledger` collected both allowlisted hosts; flags stayed false; both hosts remained PARTIAL with the module counts above; aggregate report was written. See `live/inspect-authorized.redacted.json` and `live/authorized-collection.redacted.json`. Raw payloads were not committed.
- Replaying the same intent against the same ledger was rejected: `execution intent was already consumed and cannot be replayed`.
- Refused: documentation inventory addresses (`loopback lab targets only`), allowlist/intent mismatch for an authorized-but-unlisted host, and unauthorized host intent construction. Stdout empty, exit 2.
- Resource pressure after the first live SSH host: first host report kept, second host skipped, aggregate report written. Covered by `TestInspectAuthorizedLivePressureKeepsFirstHost`.
- `HOSTSEC_LIVE_TOOLS=1` ran osquery 5.24.1, OpenSCAP 1.4.2, ClamAV 1.4.6, and YARA 4.5.2 as allowlisted control-host probes; Lynis was honestly `not_available` / `tool_not_installed`. Flags stayed false. See `live/inspect-authorized-tools.redacted.json`.
- Frozen flags rechecked on the local binary: doctor exit 1, `collector_available=false`, `scan_ready=false`; `hostsec scan` exit 2, unsupported command.

## Stayed PARTIAL (honestly)

HOSTSEC-20–24, 30, 31, 32, 33, 34, and 45 are unchanged. Official tool adapters were only probed on this amd64 lab control host under an explicit live flag; that is not a distro/VM/dual-arch tool matrix. Platform IdP, regional mTLS runners, and a completed operations center were not added. AC-02 remains PARTIAL because `hostsec scan` still does not exist as a product scanner. Non-loopback and intranet addresses remain refused.

## Unchanged BLOCKED

HOSTSEC-43 still requires MVP1-6 with AC01-15 and Linux dual-architecture runtime. Two amd64 loopback listeners are not that acceptance.

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`. `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. CI gates were not loosened. This PR is not merged. The archived cloud agent was not launched or unarchived. No connection was made to any address other than loopback lab listeners on this box.

## Quality gates

Local `PATH="/tmp/hostsec-venv/bin:$PATH" HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp7-2026-11-21-authorized-workflow make check` (no `HOSTSEC_LIVE_LINUX` / `HOSTSEC_LIVE_SSH` / `HOSTSEC_LIVE_SSH_MULTI` / `HOSTSEC_LIVE_TOOLS`) was **23/23 PASS** (Asia/Taipei, 2026-11-21 22:35 CST). See `results.json` in this directory. This local run is not a remote CI result. Frozen doctor flags were already rechecked on the local binary: `collector_available=false`, `scan_ready=false`, exit 1; `hostsec scan` and `mcp serve` stay rejected.

Remote CI for the pushed head will be recorded only after the GitHub Actions run concludes. This PR is not merged.
