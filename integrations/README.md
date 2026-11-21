# HostSec integrations

This directory holds product wrappers around the HostSec CLI. Wrappers are not the detection kernel.

- `integrations/skills/host-security-inspection/SKILL.md` is the Codex/Claude skill contract. It may call only implemented CLI commands for authorization, planning, fixture inspect, and report reading. It has no arbitrary shell capability.
- `integrations/hostsec-skill/SKILL.md` is the earlier distribution note and remains subject to the same restrictions.

`hostsec scan` and `hostsec mcp serve` stay rejected. Local identities used by `mcp stdio` or the loopback API are not a platform IdP.
