# HOSTSEC authorized-collection matrix (2026-11-21)

Scope: add a user-operated authorized collection path and prove it in the isolated Grok Bot box with two loopback OpenSSH listeners as stand-ins for distinct "remote" hosts. This is not an intranet scanner, not enterprise IdP, not regional production mTLS, and not a 3–5 host dual-architecture MVP.

Status vocabulary matches `docs/implementation/task-dag.json`. Counts after this slice: **IMPLEMENTED 36 / PARTIAL 11 / BLOCKED 1 / PLANNED 0**. No Trellis node was promoted or demoted in this round.

Doctor JSON remains frozen (`collector_available=false`, `scan_ready=false`, exit 1, 11-case CLI contract unchanged). `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. HOSTSEC-43 stays BLOCKED. Default `make check` / CI do not start lab sshd and do not set `HOSTSEC_LIVE_SSH` or `HOSTSEC_LIVE_SSH_MULTI`.

## What was reviewed

End-to-end path before this slice: assets, inventory `authorized` flag, `plan`/`intent`/`preflight`, `inspect-fixture`, `inspect-local` (single loopback host, optional SSH), local approval, evidence store, and official tool adapters. `hostsec scan` is rejected as an unsupported command; doctor flags stay false because acceptance for production scan readiness is not met.

Product gaps that this slice addresses:

- Inventory `authorized: true` was necessary but not sufficient for a collection run. There was no explicit per-run allowlist.
- `inspect-local` collected one host and did not bind a multi-host set to an execution intent.
- SSH `--identity` / `--known-hosts` were raw paths, not a per-`host_id` binding that must cover that host's loopback address and port.
- An authorized inventory host that the operator did not opt into could be selected without a separate allowlist check.
- Help/docs still under-described the user-facing distinction: authorized collection vs a general intranet scanner.

Gaps deliberately left open: platform IdP / SSO (HOSTSEC-45/32), regional production runners (HOSTSEC-31), official tool dual-arch/VM matrix (HOSTSEC-20–24), and `hostsec scan` / `scan_ready=true`. This release still refuses non-loopback addresses, including documentation and intranet IPs.

## What was implemented

New command: `hostsec inspect-authorized --file --allowlist --intent-file --out [--bindings]`. It:

1. Loads the inventory and an explicit allowlist of host IDs.
2. Requires an execution intent whose host set and profile match the allowlist exactly, then revalidates the asset snapshot through preflight.
3. Accepts only loopback lab targets in this release (`asset.LoopbackOnly` plus SSH dial loopback checks).
4. For SSH hosts, requires per-`host_id` identity and known_hosts bindings; `known_hosts` must contain a literal entry for that address:port.
5. Collects only allowlisted hosts, writing evidence under `out/hosts/<host_id>`.
6. Leaves `collector_available`, `scan_ready`, and `execution_ready` false. Deep/IR remain refused on this path.

Lab inventory now has two authorized SSH stand-ins (`linux-box-lab-ssh-001` port 2222, `linux-box-lab-ssh-002` port 2223), an authorized but unlisted host (`linux-box-lab-ssh-unlisted`), and the existing denied host. `scripts/lab_authorized_hosts.sh` starts two OpenSSH daemons on `127.0.0.1` high ports only and never starts system sshd on port 22.

## How it was tested in this lab

Default unit tests (no live SSH) cover allowlist loading, intent/allowlist mismatch, unauthorized/unknown/non-loopback refusal, missing bindings, and cross-host known_hosts rejection.

Live lab (Asia/Taipei, 2026-11-21 21:33–21:34 CST), loopback only:

- Two sshd listeners: `127.0.0.1:2222` (user `hostsec-lab`) and `127.0.0.1:2223` (user `hostsec-lab-b`). Confirmed not bound off-loopback (`live/loopback-listen.txt`).
- `hostsec inspect-authorized` collected both allowlisted hosts; flags stayed false; job status was PARTIAL (not a production PASS). See `live/inspect-authorized.redacted.json`. Raw payloads were not committed.
- Refused: unauthorized host, authorized-but-not-allowlisted host, and documentation inventory addresses (`examples/hosts.yaml`). Stdout empty, stderr `INSPECT_REJECTED`, exit 2.
- `HOSTSEC_LIVE_SSH_MULTI=1 go test` for `TestInspectAuthorizedLiveMultiHostSSH` and existing live SSH tests: pass, including cross-host known_hosts refusal.
- Frozen flags rechecked on the local binary: doctor exit 1, `collector_available=false`, `scan_ready=false`; `hostsec scan` exit 2, unsupported command.

## Stayed PARTIAL (honestly)

HOSTSEC-20–24, 30, 31, 32, 33, 34, and 45 are unchanged. This slice does not add a distro/VM/dual-arch tool matrix, platform IdP, regional mTLS runner, or a completed operations center. AC-02 remains PARTIAL because `hostsec scan` still does not exist as a product scanner.

## Unchanged BLOCKED

HOSTSEC-43 still requires MVP1-6 with AC01-15 and Linux dual-architecture runtime. Two amd64 loopback listeners are not that acceptance.

## Frozen product flags

`doctor.collector_available=false`, `scan_ready=false`. `hostsec scan` and `mcp serve` remain rejected. `inspect-fixture` still rejects `/`. CI gates were not loosened. This PR is not merged. The archived cloud agent was not launched or unarchived. No connection was made to any address other than loopback lab listeners on this box.

## Quality gates

Local `PATH="/tmp/hostsec-venv/bin:$PATH" HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp6-2026-11-21-authorized-collection make check` (no `HOSTSEC_LIVE_LINUX` / `HOSTSEC_LIVE_SSH` / `HOSTSEC_LIVE_SSH_MULTI` / `HOSTSEC_LIVE_TOOLS`): **23/23 PASS** (Asia/Taipei, 2026-11-21 21:35 CST). See `results.json` in this directory. This local run is not a remote CI result. Frozen doctor flags were rechecked on the local binary: `collector_available=false`, `scan_ready=false`, exit 1; `hostsec scan` and `mcp serve` stay rejected.

Remote CI for the pushed head will be recorded only after the GitHub Actions run concludes. This PR is not merged.
