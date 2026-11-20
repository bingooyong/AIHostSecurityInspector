# 任务 → 实现文件 → 测试 → 验收矩阵

运行：2026-11-20 Cloud Agent，基线 `eaffa02997ba24c5a3d3df7cd6445621a00b0546`，分支 `cursor/wp1-domain-approval-slice-c48d`。
环境：隔离 Linux amd64，Go 1.27.3。未连接企业主机，未部署，未合并 main。

状态词汇：IMPLEMENTED / PARTIAL / PLANNED / BLOCKED。Trellis `status` 未批量改为 completed。

| 任务 | 实现文件 | 测试命令与结果 | 验收 |
|---|---|---|---|
| HOSTSEC-00/01/02/03A | 既有归档 | 未重做 | IMPLEMENTED（既有） |
| HOSTSEC-04 | `backend/internal/domain/*`, `schemas/execution-intent-v1.schema.json` | `go -C backend test -race -count=1 ./internal/domain/` **PASS**；`python3 scripts/contracts.py` **PASS** | PARTIAL→本切片功能已实现；独立 trellis-check 子代理未另开；未 archive |
| HOSTSEC-03 | `Makefile` ldflags、`scripts/build_release.py` 双临时目录 hash | `VERSION=not-a-version` 拒绝；linux/amd64 两次 hash 一致 `2c17ee43729914f74a6fc72b988d090425efc6eb858b3d5d4c9ec6ac5d83fa5a`；产物标 **CROSS_BUILD_ONLY** | PARTIAL：版本注入与可复现交叉构建已做；未宣称 Linux 运行验收 |
| HOSTSEC-05 | `backend/internal/cli/cli.go` timeout/writer/cancel | `go -C backend test -race ./internal/cli/` **PASS**；冻结 11 条 CLI **PASS** | PARTIAL：进程内取消/timeout 已测；未做独立 SIGINT 慢子进程 |
| HOSTSEC-06 | `backend/internal/asset/snapshot.go` `diff.go`；`authorization/select.go` | `go -C backend test -race ./internal/asset/ ./internal/authorization/` **PASS**；`assets snapshot` 集成 **PASS** | PARTIAL：本地快照/差异/漂移拒绝已实现；真实主机身份复核仍待 08/14 |
| HOSTSEC-32A | `backend/internal/approval/` `backend/internal/audit/` `schemas/approval-v1.schema.json` | `go -C backend test -race ./internal/approval/ ./internal/audit/` **PASS**（含双 goroutine 至多一次消费） | PARTIAL：本地 ed25519 验证器+journal 已实现；企业 OS 身份/密钥托管仍为启用 BLOCKED |
| HOSTSEC-07 | `backend/internal/planner/intent.go` CLI `intent`/`preflight` | `go -C backend test -race ./internal/planner/` **PASS**；intent schema 集成 **PASS**；`execution_ready` 仍不出现/不为 true | PARTIAL：可签名意图+Preflight 已实现；限额未 enforced，无 Collector 故不可执行 |
| HOSTSEC-42 | `scripts/verify.py` 证据目录隔离、CI artifact 改 `docs/05-testing/evidence/ci` | 本地 unit/vet/boundaries/layout/integration/contracts/build **PASS**；`make lint`/`govulncheck` **NOT_RUN**（本环境未装 tools）；远端 GitHub Actions **UNVERIFIED** | PARTIAL |
| 00-bootstrap-guidelines | `.trellis/spec/frontend/*.md` 按 WP7 约束填写 | 文档审查；无 frontend 工程、无空 npm | PARTIAL：规范已填，frontend 实现仍 PLANNED |
| HOSTSEC-08–45/43 | 未在本切片实现采集/规则/AI/MCP/Web | 不冒充 | PLANNED；14/32/45 等企业环境 **BLOCKED** 直至授权测试床 |

## 本机已运行（cwd=/workspace 除非注明）

| 命令 | cwd | 退出码 |
|---|---|---|
| `go -C backend test -race -count=1 ./...` | /workspace | 0 |
| `go -C backend vet ./...` | /workspace | 0 |
| `go -C backend run ./tools/check-boundaries` | backend | 0 |
| `python3 scripts/contracts.py` | /workspace | 0 |
| `python3 scripts/integration.py` | /workspace | 0（30 CLI 进程） |
| `python3 scripts/check_layout.py` | /workspace | 0 |
| `python3 scripts/build_release.py` | /workspace | 0 |
| `VERSION=not-a-version python3 scripts/build_release.py` | /workspace | 1（预期） |
| `make lint` / `govulncheck` | — | NOT_RUN |
| GitHub Actions | — | UNVERIFIED |
