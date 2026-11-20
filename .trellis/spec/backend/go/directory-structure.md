# Multi-project repository and Go module layout

## 1. Scope / trigger

The repository has a nested Go module and future frontend/Agent integrations. The repository root is not a Go module. Authoritative design: docs/02-architecture/REPOSITORY-LAYOUT.md and ADR-008.

## 2. Signatures

Root commands: make build/test/vet/lint/check/release. Direct module commands: go -C backend test -race ./..., go -C backend vet ./..., go -C backend run ./tools/check-boundaries. CLI remains build/hostsec with unchanged flags and output.

## 3. Contracts

backend/go.mod declares github.com/bingooyong/AIHostSecurityInspector/backend. All project imports include /backend. backend/cmd/hostsec is the current thin entry point; backend/internal/{cli,asset,policy,planner} own current behavior. backend/tools/check-boundaries is Go tooling. backend/.golangci.yml owns Go lint configuration. Root schemas/examples/scripts are shared repository resources; Python tools derive root from __file__ and use explicit backend cwd for Go commands. Root build/ remains the artifact/tool directory. Frontend/integrations/deploy are future boundaries, not existing runnable applications.

## 4. Validation and errors

| Condition | Required outcome |
|---|---|
| root go.mod/go.sum/go.work or root cmd/internal/pkg appears | fail the layout gate |
| Go source outside backend (including root scripts) | fail the layout gate |
| old project import without /backend | fail the layout gate/build |
| module dependencies/config unavailable | fail nonzero; do not silently fall back to a root module |
| original V1 or bootstrap evidence changes | fail source/history integrity checks |

## 5. Good / base / bad

Good: make check from repo root; go -C backend test ./... without root module hacks. Base: multiple backend/cmd binaries share only relevant internal packages. Bad: separate empty Go modules per planned binary, root replace/GO111MODULE workaround, or Collector importing AI/DB dependencies.

## 6. Tests required

Existing regression tests and 11 real CLI cases must retain stdout/stderr/exit exactly after migration. Test the module directly and via root Makefile; check module imports, fixture paths, CI setup-go version/cache paths, SBOM/build artifacts and new source hashes. Preserve old bootstrap evidence. Collector implementation later adds go list -deps allowlist tests; current internal visibility is not a security boundary.

## 7. Wrong vs correct

Wrong: go test ./... from the repository root containing an unrelated hidden module. Correct: go -C backend test ./... or make test. Wrong: runtime looks for ../../examples by cwd. Correct: CLI accepts explicit --file; source-relative test fixture paths are test-only.
