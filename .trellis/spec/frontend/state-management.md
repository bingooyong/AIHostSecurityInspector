# State Management

## 1. Scope / trigger

Client state for WP7. Server remains source of truth for assets, plans, evidence, and approvals.

## 2. Signatures

Local UI state (modals, table filters) may live in component state. Resource state comes from the API cache keyed by server IDs.

## 3. Contracts

- Do not keep a second copy of RuleResult/Finding that can diverge from the last server payload.
- Optimistic updates are forbidden for authorization, approval consume, and scan start.
- URL query params may restore filters, not credentials.

## 4. Validation and errors

Hydration from localStorage must ignore unknown fields and must not restore secrets.

## 5. Good / base / bad

Good: server cache with explicit invalidation after approval. Bad: a global store that sets `execution_ready=true` in the browser.

## 6. Tests required

State tests proving a 403 cannot be overwritten by cached success.

## 7. Wrong vs correct

Wrong: derive “host is safe” from the absence of findings in client state. Correct: show coverage, UNKNOWN, and human review from the payload.
