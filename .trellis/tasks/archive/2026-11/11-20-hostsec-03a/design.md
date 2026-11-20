# Design

Authoritative first-slice contract: docs/03-sdd/CLI-SDD.md. Domain responsibilities are asset validation, fixed policy descriptions and authorized offline planning, with CLI as the thin entry point. Inputs are strict YAML/JSON; output plan is JSON-schema versioned. Runtime has no executor or network client. Safety relies on no execution capability plus fail-closed selection; future run authorization must be independently implemented and rechecked. Existing V1 source remains unchanged. Rollback removes only new first-slice files.
