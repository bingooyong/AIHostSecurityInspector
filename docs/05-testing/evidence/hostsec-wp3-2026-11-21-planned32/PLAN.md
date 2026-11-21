# 32 项 PLANNED 分阶段执行计划（本次续跑）

基线 HEAD `73cfbce7f3fefe0abe6fbf97b296d3520826c7d3`。权威依赖：`docs/implementation/task-dag.json`。
用户口中的「14 软件包」在 DAG 中是 **HOSTSEC-38**；**HOSTSEC-14 是 SSH Transport**。本次按 DAG 执行，不改产品依赖。

安全门：不改 doctor 冻结输出（`collector_available=false`、`scan_ready=false`）；`hostsec scan` 仍非零。端到端只走 **fixture-inspect**（显式 `--root`，拒绝 `/`）和库测试。不连接企业主机、不 SSH 到用户目标。

## 波次

| 波次 | 节点 | 性质 |
|---|---|---|
| A | 13 安全配置、37 文件元数据、38 软件包、16 Manifest；32A 已有实现改 PARTIAL | 本地 fixture/库 |
| B | 18 Finding、44 基线、17 九条规则、40 工具执行器接口 | 库级求值 |
| C | 36 本地编排、19 报告、CLI `inspect-fixture` | 可测试链路，仍非 scan_ready |
| D | 14 SSH 策略（无企业目标）、20–24 Adapter 缺工具、25–28 AI 默认关闭、29 Skill、39 情报、41 包路径防护 | 能做多少做多少 |
| E | 30 MCP、31 Runner、32 平台审批、33–35 Web、43 总体验收、45 RBAC | 缺协议/区域/企业身份则 BLOCKED |

完整验收（IMPLEMENTED）需要真实 VM/SSH/企业身份的节点本轮最多 PARTIAL 或 BLOCKED。
