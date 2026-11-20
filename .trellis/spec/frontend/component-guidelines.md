# Component Guidelines

## 1. Scope / trigger

WP7 React components. Not applicable until HOSTSEC-34.

## 2. Signatures

Components receive already-authorized view models from the API client. They never compute RuleResult or rewrite severity.

## 3. Contracts

- Presentational components do not fetch.
- Findings always show evidence refs, review status, and limitations.
- Destructive or privileged actions require an explicit confirmation that still calls a server-checked endpoint.
- Do not render raw collector output, private keys, or unredacted argv.

## 4. Validation and errors

Unknown enum values render as UNKNOWN/unavailable, not as success. Missing evidence cannot be shown as a clean bill of health.

## 5. Good / base / bad

Good: FindingCard with required human-review badge. Bad: a green checkmark when `ai_status=failed` or `collection_status=failed`.

## 6. Tests required

Component tests for empty, forbidden, and partial-scan fixtures from `schemas/`.

## 7. Wrong vs correct

Wrong: client-side allow-list of host IPs. Correct: host_id from the API, never free-form scan targets.
