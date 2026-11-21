# Reviewed YARA rule pack

This directory is the only rule set the HostSec YARA adapter accepts in live
lab tests. Rules are reviewed before they are added.

Allowed:

- Local string/pattern matches with a timeout
- The `hostsec_harmless` rule, which detects only the `harmless_marker` test string

Rejected:

- `include` directives
- External variables
- Rules fetched from the network at scan time
- YARA-X (not evaluated as a replacement in this pack)

Source: written for HostSec lab verification; not an upstream threat pack.
