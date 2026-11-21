# Remaining BLOCKED / UNVERIFIED after query-audit slice

## HOSTSEC-43 — 真实环境验证 (BLOCKED)

No authorized customer/enterprise Linux VM, SSH known_hosts, production window, or live Collector runtime. Isolation forbids connecting to real user hosts. Fixture include-following and loopback query APIs are not substitutes.

## UNVERIFIED (keep PARTIAL)

- Platform identity (OIDC/SSO) and enterprise RBAC cache invalidation
- HTTP MCP with verified auth; official MCP SDK
- Durable audit journal for the local API (in-memory events only)
- Runner mTLS and regional isolation
- Production Web TLS / WAF / hosted Playwright
- Real SSH transport
- Doctor wording vs inspect-fixture remains the frozen CLI contract (cannot change stdout without breaking the 11 frozen cases)

## Explicitly not done

- `hostsec scan` still unsupported
- `mcp serve` still unsupported
- `collector_available`, `scan_ready`, and `execution_ready` stay false
- No production credentials or live host output

## CI note

Previous public-repo PR CI PASS: https://github.com/bingooyong/AIHostSecurityInspector/actions/runs/44871663768 (head `ff8800e`). A new push starts a new PR CI run; this directory records local `make check` only and does not claim that future run passed.
