# Execution plan

1. Review CLI-SDD and backend specs; implement strict asset loader and relation checks.
2. Implement fixed four-profile catalog and authorized planner with all-or-nothing target validation.
3. Wire runnable version/doctor/assets/plan CLI and safe JSON/errors; examples use documentation addresses only.
4. Add schema contracts, meaningful negative tests and CLI smoke coverage.
5. gofmt; go test -race ./...; go vet ./...; golangci-lint run ./...; build local/Linux amd64/arm64.
6. Independent Trellis check/adversarial review, integration schema/security checks; correct failures.
7. Persist logs, update scope/status and README. Keep unimplemented components PLANNED.

Ownership: implement subagent owns cmd/, internal/, go.mod/go.sum, schemas/, examples/ and Go tests. Main owns docs, scripts, CI, task DAG and evidence. No git commits/push or unrelated file edits from subagents.

## 本轮完成证据
状态 IMPLEMENTED。需求/设计/实现/自测/独立审计/验收均在交付范围内完成；详见
- docs/05-testing/evidence/bootstrap/results.json
- docs/security/CLI-INDEPENDENT-REVIEW.md
- docs/05-testing/ACCEPTANCE-RESULTS.md
