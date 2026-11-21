# Journal 1

## 2026-11-20 WP1 slice

Implemented HOSTSEC-04 domain models, HOSTSEC-06 snapshots, HOSTSEC-32A local approval/journal, HOSTSEC-07 intent/preflight, versioned reproducible cross-build, and frontend planned specs. Did not archive tasks: independent check and collector runtime remain. No enterprise hosts scanned. PR on `cursor/wp1-domain-approval-slice-c48d`.

## 2026-11-21 continuation

CI root cause is GitHub Actions billing/spending-limit: jobs never assigned a runner. Did not mark remote CI PASS. Rebuilt golangci-lint with go1.27.3, local `make check` 16/16 PASS. Added fixture-only HOSTSEC-08/09/10 collectors (identity/process/network) without live `/` or packet probes. DAG 08/09/10 PARTIAL; still 4/48 IMPLEMENTED. No archive, no merge, no new PR, no subscriptions.
