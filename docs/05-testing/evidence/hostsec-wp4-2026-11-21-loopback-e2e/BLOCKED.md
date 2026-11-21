# Remaining BLOCKED / UNVERIFIED after loopback-e2e slice

## HOSTSEC-43 — 真实环境验证 (BLOCKED)

No authorized customer/enterprise Linux VM, SSH known_hosts, production window, or live Collector runtime. Isolation policy forbids connecting to real user hosts, reading live `/etc/shadow`, or deploying. Local fixture inspect, loopback API, and Playwright against 127.0.0.1 are not substitutes.

## UNVERIFIED (keep PARTIAL)

- Platform identity (OIDC/SSO), key custody, and enterprise RBAC cache invalidation
- HTTP MCP with verified auth (stdio only; initialize/pagination/idempotency are local JSON-RPC)
- Official MCP SDK
- Runner mTLS, regional isolation, signed-task transport over the network
- Production Web TLS, WAF, and Playwright E2E against a hosted API with platform identity
- Real SSH transport (`golang.org/x/crypto/ssh` remains globally forbidden except a future deliberate gate)
- npm production CVE hardening beyond lockfile install; frontend audit findings are not claimed fixed

## Explicitly not done

- `hostsec scan` still unsupported
- `mcp serve` still unsupported
- `collector_available`, `scan_ready`, and `execution_ready` stay false
- No production credentials, purchases, or egress of sensitive host output

## CI note

Previous public-repo PR CI PASS: https://github.com/bingooyong/AIHostSecurityInspector/actions/runs/44864375014 (head `759cddc`). A new push starts a new PR CI run; this directory records local `make check` only and does not claim that future run passed.
