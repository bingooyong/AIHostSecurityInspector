# Hook Guidelines

## 1. Scope / trigger

Data-fetching and UI hooks for the planned frontend.

## 2. Signatures

Hooks wrap the typed API client. They propagate cancellation and never retry mutating approval/scan requests unless the server documents idempotency keys.

## 3. Contracts

- Query hooks expose loading/empty/error/forbidden.
- Mutation hooks disable double submit.
- No hook may call Collector, SSH, or shell APIs.
- Tokens stay in httpOnly cookies or the API session; hooks do not log Authorization headers.

## 4. Validation and errors

Failed fetches leave previous data untouched unless the server says the resource was deleted. 403 is distinct from empty.

## 5. Good / base / bad

Good: `usePlan(hostId)` with abort on unmount. Bad: a `useExec(cmd: string)` helper.

## 6. Tests required

Hook tests with a fake fetch that returns 401/403/timeout fixtures.

## 7. Wrong vs correct

Wrong: storing approval-id in the hook and treating it as permission. Correct: the server verifies the signed approval.
