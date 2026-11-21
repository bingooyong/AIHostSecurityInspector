# 任务 → 实现文件 → 测试 → 验收矩阵

运行：2026-11-21 Cloud Agent continuation（用户 10:12 Asia/Taipei 授权单次续跑），基线 HEAD `a598b208355a85e943ce10043b8b97398ce013bf`，分支 `cursor/wp1-domain-approval-slice-c48d`，PR https://github.com/bingooyong/AIHostSecurityInspector/pull/1。
环境：隔离 Linux amd64，Go 1.27.3。未连接企业主机，未部署，未合并 main，未新建 Cloud Agent/PR，未订阅 CI。

状态词汇：IMPLEMENTED / PARTIAL / PLANNED / BLOCKED。未 archive Trellis 任务。

## CI 根因（远端 GitHub Actions）

只读查询最新 run `44849763003`（head `a598b208`）：`conclusion=failure`，job `offline-cli` `runner_id=0`，`steps=0`，约 2s。注解原文：

> The job was not started because recent account payments have failed or your spending limit needs to be increased. Please check the 'Billing & plans' section in your settings

未替用户付款、未改账单、未绕过门禁、未反复重跑。**远端 CI 不得标 PASS。** 本地 `make check` 通过不等于远端 CI 通过。

## DAG 完成计数

- IMPLEMENTED（归档/既有）：HOSTSEC-00/01/02/03A = **4/48**
- 本轮新增 IMPLEMENTED：**0**（fixture 采集与双架构 VM 人工核对未齐；SQLite 未接 CLI/scan、无签名，不降验收归档）
- 本轮 PARTIAL：HOSTSEC-11/12/15；既有 08/09/10/04–07/32A/42 保持 PARTIAL

| 任务 | 实现文件 | 测试命令与结果 | 验收 |
|---|---|---|---|
| HOSTSEC-00/01/02/03A | 既有归档 | 未重做 | IMPLEMENTED（既有） |
| HOSTSEC-04–07/32A/08/09/10 | 上一切片 | 本轮回归 `go test -race ./...` **PASS** | PARTIAL，未 archive |
| HOSTSEC-11 | `backend/internal/collector/linux/accounts.go` | `go -C backend test -race ./internal/collector/linux/` **PASS**（passwd/group/UID0/sudo/authorized_keys SHA-256 指纹/登录；不读 shadow/私钥；符号链接逃逸不泄露；sudo EACCES→partial；拒绝 live `/`；timeout） | PARTIAL：合成 fixture；真实主机 passwd/shadow **未读**；双架构 VM **NOT_RUN** |
| HOSTSEC-12 | `backend/internal/collector/linux/persistence.go` | 同上 **PASS**（unit 文件解析、timer/cron/rc/profile 元数据/模块；nosystemd→not_applicable；不执行 ExecStart；at=not_available） | PARTIAL：无 systemd/cron 真机核对 |
| HOSTSEC-15 | `backend/internal/storage/`、`backend/internal/evidence/store.go` | `go -C backend test -race ./internal/storage/ ./internal/evidence/` **PASS**（迁移幂等/checksum、只追加、0700/0600、孤立对象隔离、取消不提交、ENOSPC 分类、并发不同 ID；integrity=unverified） | PARTIAL：库级隔离原型；未接 CLI/scan；无 Manifest/签名；磁盘满为错误分类而非真实配额设备 |
| HOSTSEC-42 | 既有 GOTOOLCHAIN 与 collector 门禁 | 本地 `make check` 见 `results.json` | PARTIAL + 远端账单 BLOCKED |
| HOSTSEC-13/14/16–45/43 | 未在本轮实现 | 不冒充 | PLANNED 或企业环境 BLOCKED |

## 本机已运行（cwd=/workspace 除非注明）

| 命令 | cwd | 退出码 |
|---|---|---|
| `go -C backend test -race -count=1 ./internal/collector/linux/ ./internal/storage/ ./internal/evidence/` | /workspace | 0 |
| `golangci-lint run ./...` | backend | 0 |
| `go -C backend run ./tools/check-boundaries` | backend | 0 |
| `HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp2-2026-11-21-h11-15 make check` | /workspace | 0（16/16 PASS） |
| GitHub Actions HostSec quality gates | GitHub | 失败；未启动 runner |

交叉编译仍为 CROSS_BUILD_ONLY，不是 Linux 采集运行验收。`scan_ready`/`execution_ready`/`collector_available` 保持 false。预检/fixture 成功不是执行许可。
