# Host Security Inspection Skill

This skill is a product integration wrapper. Detection, authorization, rules, and evidence stay in the HostSec Go kernel. The skill may only invoke already implemented CLI commands. It has no shell, SSH, SQL, or tool-arbitrary execution capability.

## Allowed commands

The skill may call only these implemented CLI entry points:

- `hostsec version`
- `hostsec doctor`
- `hostsec assets validate|list`
- `hostsec plan` (dry-run only)
- `hostsec intent`
- `hostsec preflight`
- `hostsec inspect-fixture --file PATH --host ID --root ABS_FIXTURE --out DIR --profile quick|standard`

`inspect-fixture` reads a caller-supplied synthetic fixture root. It must reject `/`, must not set `collector_available`, `scan_ready`, or `execution_ready`, and must not SSH or scan an enterprise host. Deep and incident-response profiles still require a verified approval and must not be executed by this skill.

Approved flow: authorize assets, build a dry-run plan, optionally build intent/preflight, then `inspect-fixture`, then read the produced report. The skill must not invent evidence, approvals, or integrity.

## Forbidden

- Arbitrary shell, `bash -c`, `execute_shell`, `ssh_exec`, SQL, VQL, or unlisted CLI flags
- Passing model output through as a command
- Sending raw logs, full argv, credentials, or private keys
- Inventing an approval ID or using the same principal as requester and approver
- Enabling AI by default or treating model text as findings
- Calling `hostsec scan` or `hostsec mcp serve`

AI stays disabled unless a later, separately approved path is enabled. If analysis is requested, only a minimized allowlisted view may be sent, and citations must stay inside the current scan/host evidence ID set.
