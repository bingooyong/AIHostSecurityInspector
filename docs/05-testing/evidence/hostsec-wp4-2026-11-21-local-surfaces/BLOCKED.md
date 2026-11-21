# Remaining BLOCKED / UNVERIFIED after local-surfaces slice

## HOSTSEC-43 — 真实环境验证 (BLOCKED)

No authorized customer/enterprise Linux VM, SSH known_hosts, production window, or live Collector runtime. Isolation policy forbids connecting to real user hosts, reading live `/etc/shadow`, or deploying. Local fixture inspect and loopback API are not substitutes.

## UNVERIFIED (keep PARTIAL)

- Platform identity (OIDC/SSO), key custody, and enterprise RBAC cache invalidation
- HTTP MCP with verified auth (stdio only)
- Runner mTLS, regional isolation, signed-task transport over the network
- Production Web TLS, CORS, WAF, and Playwright E2E against a hosted API
- Real SSH transport (`golang.org/x/crypto/ssh` remains globally forbidden except a future deliberate gate)
- GitHub Actions remote PASS: billing-blocked runners are not retried; local `make check` ≠ remote CI PASS
- npm production CVE hardening beyond lockfile install; frontend audit findings are not claimed fixed

## Explicitly not done

- `hostsec scan` still unsupported
- `mcp serve` still unsupported
- No production credentials, purchases, or egress of sensitive host output
