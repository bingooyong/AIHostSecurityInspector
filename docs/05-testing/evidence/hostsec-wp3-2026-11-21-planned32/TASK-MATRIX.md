# 32 项 PLANNED 续跑矩阵（2026-11-21）

基线 HEAD `73cfbce7f3fefe0abe6fbf97b296d3520826c7d3`。隔离 fixture / 本地库测试；无真实企业主机、无 SSH 拨号、无生产凭据。doctor `collector_available=false`、`scan_ready=false`；`hostsec scan` 仍非零。

| ID | 原状态 | 本轮 | 依赖 | 实现入口 | 测试 | 验收局限 |
|---|---|---|---|---|---|---|
| HOSTSEC-13 | PLANNED | PARTIAL | 08 | `backend/internal/collector/linux/security.go` | include 未解析≠完整策略；缺失≠合规 | 无真实 VM |
| HOSTSEC-37 | PLANNED | PARTIAL | 08 | `files.go` | 白名单、symlink 不跟随 | 无真实 VM；setuid 位在本 FS 上可能被剥离 |
| HOSTSEC-38 | PLANNED | PARTIAL | 08 | `packages.go` | 解析 dpkg status，不安装 | 无 rpm 解析、无真实主机包库 |
| HOSTSEC-16 | PLANNED | PARTIAL | 15 | `evidence/manifest.go` | 篡改/缺对象/缺 raw 不伪造摘要 | 无来源签名 |
| HOSTSEC-32A | PLANNED | PARTIAL | 04,06 | approval/audit + nonce ledger | 伪造/过期/重放/同人审批拒绝 | 未接入平台身份；preflight 未消费 ledger |
| HOSTSEC-18 | PLANNED | PARTIAL | 04,16 | `findings/builder.go` | UNKNOWN 不生成 Finding；未验证证据拒绝 FAIL | 无企业扫描流水线 |
| HOSTSEC-44 | PLANNED | PARTIAL | 16,06 | `baseline/store.go` | 首次扫描只能是 candidate | 无已批准企业基线 |
| HOSTSEC-17 | PLANNED | PARTIAL | 18,44 | `rules/engine.go` + 9 YAML | 正/反/缺证据/缺基线/N/A | 规则包未签名 |
| HOSTSEC-40 | PLANNED | PARTIAL | 04 | `tools/executor.go` | 缺工具 ≠ 干净；拒绝任意工具 | 不 os/exec |
| HOSTSEC-20–24 | PLANNED | PARTIAL | 40,16 | `adapter/adapter.go` | 全部 not_available | 本环境无 osquery/Lynis/OpenSCAP/ClamAV/YARA |
| HOSTSEC-14 | PLANNED | PARTIAL | 08,32A | `transport/ssh/policy.go` | known_hosts/root/任意 exec 拒绝 | 无 SSH 拨号、无测试容器；边界门禁仍禁止 crypto/ssh |
| HOSTSEC-36 | PLANNED | PARTIAL | 07–14,16,17,32A,37,38 | `orchestrator/inspect.go` | fixture inspect；拒绝 `/` 与 deep | 非 scan_ready；无 VM 端到端 |
| HOSTSEC-19 | PLANNED | PARTIAL | 17,16,36 | `report/report.go` | JSON+Markdown | 仅 fixture |
| HOSTSEC-25–28 | PLANNED | PARTIAL | 18,19,16 | `analyzer/` | 默认 disabled；越权引用拒绝 | 无批准模型端点 |
| HOSTSEC-29 | PLANNED | PARTIAL | 28,19,36 | `integrations/hostsec-skill/SKILL.md` | 文档约束 | 未安装到客户端 |
| HOSTSEC-39 | PLANNED | PARTIAL | 38,17 | `intel/correlate.go` | 缺情报=UNKNOWN | 无发行版 epoch 情报库 |
| HOSTSEC-41 | PLANNED | PARTIAL | 16,19 | `bundle/verify.go` | 拒绝 symlink | 无 tar.zst/签名导入 |
| HOSTSEC-30 | PLANNED | BLOCKED | 29,32,45 | — | — | 无 MCP 协议落地与企业身份 |
| HOSTSEC-31 | PLANNED | BLOCKED | 30,41,32 | — | — | 无区域 Runner 环境 |
| HOSTSEC-32 | PLANNED | BLOCKED | 32A,19 | — | — | 无平台审批服务 |
| HOSTSEC-33–35 | PLANNED | BLOCKED | 30–32,45,44 | — | — | 无 Web/前端工程与身份 |
| HOSTSEC-45 | PLANNED | BLOCKED | 32 | — | — | 无企业 RBAC |
| HOSTSEC-43 | PLANNED | BLOCKED | 29,19,36,28,42,39 | — | — | 无企业部署/真实 VM 验收 |

新增可运行入口：`hostsec inspect-fixture --file --host --root --out --profile quick|standard`。
