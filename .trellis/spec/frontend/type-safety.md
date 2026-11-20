# Type Safety

## 1. Scope / trigger

TypeScript types for API/Schema consumption.

## 2. Signatures

Generate or hand-write types from `schemas/*.schema.json`. Do not silently widen enums. `execution_ready` remains boolean as returned by the server; the client must not coerce missing to true.

## 3. Contracts

- IDs are branded strings, not IPs.
- Rule outcomes are `"PASS" | "FAIL" | "UNKNOWN" | "NOT_APPLICABLE"` only.
- Confidence is an integer 0–100, never a float probability used as certainty.
- Optional AI fields are absent or typed; `ai_status !== "success"` means `ai_assessment` is null.

## 4. Validation and errors

Runtime parse failures become UI errors, not defaulted PASS. AdditionalProperties from the server are ignored only after an explicit strip step, not treated as trusted extras.

## 5. Good / base / bad

Good: zod/io-ts (or equivalent) aligned with Schema. Bad: `as ScanResult` on `fetch().then(r => r.json())`.

## 6. Tests required

Parser tests for each negative Schema fixture used by `scripts/contracts.py`.

## 7. Wrong vs correct

Wrong: duplicate HostSec domain rules in TypeScript. Correct: validate shape, display, and send mutations; Go remains the decision kernel.
