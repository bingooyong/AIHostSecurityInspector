# 任务 → 实现文件 → 测试 → 验收矩阵

运行：2026-11-21 Cloud Agent continuation，基线 `eaffa02997ba24c5a3d3df7cd6445621a00b0546`，分支 `cursor/wp1-domain-approval-slice-c48d`，续跑前 HEAD `8bf8d081d6f75746d9a739adc35fdd6360398fb6`。
环境：隔离 Linux amd64，Go 1.27.3。未连接企业主机，未部署，未合并 main，未新建 PR。

状态词汇：IMPLEMENTED / PARTIAL / PLANNED / BLOCKED。未 archive Trellis 任务。

## CI 根因（远端 GitHub Actions）

PR job `44758732257/136365310445` 与 main job `44728292835/136261206869` 均约 3s 失败，`steps=[]`，`runner_id=0`，job log 404。

`gh run view` 注解原文：

> The job was not started because recent account payments have failed or your spending limit needs to be increased. Please check the 'Billing & plans' section in your settings

全部 HostSec quality gates 运行（含 bootstrap 起）同一账单阻塞。**不是本 PR 代码失败。** 未删除/跳过门禁。远端 CI **不得标 PASS**。需用户在 GitHub Billing & plans 处理付款失败或提高 spending limit。

## DAG 完成计数

- IMPLEMENTED（归档/既有）：HOSTSEC-00/01/02/03A = **4/48**
- 本轮新增 IMPLEMENTED：**0**（fixture 采集与双架构 VM 人工核对未齐，不降验收归档）
- 本轮 PARTIAL：HOSTSEC-08/09/10；HOSTSEC-42 本地门禁补齐但仍被远端账单 BLOCKED

| 任务 | 实现文件 | 测试命令与结果 | 验收 |
|---|---|---|---|
| HOSTSEC-00/01/02/03A | 既有归档 | 未重做 | IMPLEMENTED（既有） |
| HOSTSEC-04–07/32A | 上一切片 | 本轮回归 `go test -race ./...` **PASS** | PARTIAL，未 archive |
| HOSTSEC-08 | `backend/internal/collector/linux/system.go` | `go -C backend test -race ./internal/collector/linux/` **PASS**（发行版/内核/资源/boot/指纹/超时/容器视图/拒绝 live `/`） | PARTIAL：fixture 已实现；双架构测试 VM 人工核对 **NOT_RUN**；`doctor.collector_available` 仍 false |
| HOSTSEC-09 | `backend/internal/collector/linux/process.go` | 同上 **PASS**（PID/PPID/UID/hash、`exe_missing`≠`permission_denied`、deleted、kernel_thread、timeout） | PARTIAL：无真实 PID 竞态 VM |
| HOSTSEC-10 | `backend/internal/collector/linux/network.go` | 同上 **PASS**（IPv4 listen→PID、未解析 inode 不编造、DNS/route/firewall 文件、timeout；无 `net` 探测） | PARTIAL：无真实网络命名空间 VM |
| HOSTSEC-42 | `Makefile` tools GOTOOLCHAIN、`check-boundaries` collector 依赖门禁 | 本地 `make check` **PASS**（含 lint/govulncheck/SBOM）；远端 Actions **FAIL/账单** | PARTIAL + 远端 BLOCKED |
| HOSTSEC-11–45/43 | 未实现 | 不冒充 | PLANNED；14/32/36/45 企业环境 BLOCKED |

## 本机已运行（cwd=/workspace 除非注明）

| 命令 | cwd | 退出码 |
|---|---|---|
| `make tools`（GOTOOLCHAIN=go1.27.3） | /workspace | 0 |
| `golangci-lint run ./...` | backend | 0 |
| `go -C backend test -race -count=1 ./...` | /workspace | 0 |
| `go -C backend vet ./...` | /workspace | 0 |
| `go -C backend run ./tools/check-boundaries` | backend | 0 |
| `HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp2-2026-11-21 make check` | /workspace | 0（16/16 PASS） |
| GitHub Actions HostSec quality gates | GitHub | 失败；未启动 runner |

govulncheck：应用代码 **No vulnerabilities found**。stdlib 公告 GO-2026-6859（`net/http` MaxBytesHandler 竞态）存在于 go1.27.3；本切片禁止 `net/http` 导入，符号扫描未命中。不可达不等于组件无公告。

交叉编译仍为 CROSS_BUILD_ONLY，不是 Linux 采集运行验收。`scan_ready`/`execution_ready`/`collector_available` 保持 false。
