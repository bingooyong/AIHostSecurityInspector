# HostSec 本轮执行报告

> 时点说明：本文记录首次bootstrap时的目录与验证；当前Go工程已迁入backend/，当前布局见docs/02-architecture/REPOSITORY-LAYOUT.md，新验证见evidence/layout-migration，原bootstrap日志保留。

日期2026-11-20。MODE=BOOTSTRAP + INVENTORY + DESIGN。**本轮基线与首个离线CLI切片已交付；首期MVP整体未交付。** 未连接主机、未执行扫描、未部署或发布。Go工程和所有新文档可在工作区复核，未创建Git提交/推送。

## 十二项交付

| 交付 | 状态 | 文件/证据 |
|---|---|---|
| 1 仓库盘点 | IMPLEMENTED | [00-project-inventory](../00-project-inventory.md)、environment.json；Trellis0.6.17，非空库不覆盖 |
| 2 需求基线 | IMPLEMENTED | [PRD](../01-product/PRD.md)、BUSINESS-SCOPE.md，R01–14→任务/AC |
| 3 技术架构 | IMPLEMENTED | 02-architecture三文档、官方工具调研；无复杂基础设施 |
| 4 安全边界 | IMPLEMENTED（设计） | 04-security边界/威胁/数据治理；实际控制逐模块验收 |
| 5 详细设计 | IMPLEMENTED（设计） | 03-sdd领域/采集/规则/证据/AI/CLI/MCP/Storage八文档；未来实现均标PLANNED |
| 6 ADR | IMPLEMENTED | ADR-001–007记录原设计/原因/影响/测试 |
| 7 Trellis DAG | IMPLEMENTED | [TASK-DAG](TASK-DAG.md)、task-dag.json；48节点、真实任务、全套文档/输入/输出/验收/测试/风险/并行/证据 |
| 8 MVP计划 | IMPLEMENTED | [MVP-PLAN](MVP-PLAN.md)，六项完成条件和跨阶段前置 |
| 9 测试验收计划 | IMPLEMENTED | TEST-STRATEGY、ACCEPTANCE-CRITERIA/RESULTS、13类对抗审计 |
| 10 工程结构 | IMPLEMENTED | cmd/hostsec、internal/{cli,asset,policy,planner}、schemas/examples/scripts/CI；未来不建空壳 |
| 11 可运行CLI骨架 | IMPLEMENTED（03A范围） | version/doctor/assets validate/list/plan，四Profile，strict YAML/JSON，资产→授权→离线计划链路 |
| 12 本轮报告 | IMPLEMENTED | 本文件及[验证结果](../05-testing/evidence/bootstrap/results.json)/独立审查 |

## 实际行为

make build后可运行build/hostsec。assets支持显式授权、稳定非IP主机ID、Profile白名单、严格单文档和大小/深度/记录限制；拒绝null/重复/别名/未知字段/非普通文件，整组越权全部拒绝。JSON结果stdout，结构化错误stderr，不回显输入secret。

plan从不连接目标，execution_ready=false、limits.enforced=false；深扫/IR仅展示有效审批与维护窗口要求。doctor明确Collector未实现并退出1；不在Linux上也假报就绪。扫描/SSH/SQLite/证据/规则/报告/AI/MCP命令尚不可用，未知入口非零。

## 来源与一致性

已读取V1目录22文件，源manifest摘要复核全部未变；另读docs/SKILL.md。HTML后移、四Profile累积、证据必须真实引用、首次无基线UNKNOWN、原始/标准化规则/脱敏AI分流、只读副作用、有效审批提前、YAML维护库与版本化许可均已记录ADR。原先口头23为误计，以22项manifest为准。

## 验证和审计

正式本地13门禁通过：gofmt、vet、race、lint、AST边界、CLI构建、27进程Schema/越权/注入、未来结果Schema形状正反、DAG/来源/链接、govulncheck、SBOM、Linux双架构ELF/摘要、空白检查。[独立代码审查](../security/CLI-INDEPENDENT-REVIEW.md)复现null和IP主机ID两项，均修复并复验；独立基线审查补齐48任务模块SDD上下文。完整[对抗审计](../security/ADVERSARIAL-REVIEW.md)逐项说明已验与PLANNED。

首次漏洞扫描因全局旧分析工具不支持Go1.27而失败，attempt1原日志保留；已在build/tools用当前Go重建固定govulncheck再通过，没有替换全局工具。零可达漏洞并非所有组件零告警：Go1.27.3 stdlib的GO-2026-6859未被当前CLI导入，修复版本1.27.4，风险R14要求新增HTTP能力前升级并重扫。

1000主机解析本机CLI单样本约25.6ms/13.4MiB最大RSS，三次benchmark约14.5–14.7ms/op（累计分配约6.66MB/op）；这些是离线解析证据，不是Linux Collector性能验收。Linux amd64/arm64交叉构建通过，仅证明编译。GitHub CI已配置，未在远端运行。

## 完成状态与下一顺序

HOSTSEC-00/01/02与03A为IMPLEMENTED；03/04/05/06/07/42因已有基础贡献为PARTIAL，其完整验收仍待后续独立切片。其余业务节点PLANNED。主控整体PARTIAL；原bootstrap-guidelines仅backend初始规范已补，frontend无实现，保持PARTIAL不虚构惯例。

下一步按DAG完成完整领域/CLI契约、资产治理/策略、本地有效审批与审计，随后08系统采集、15/16证据并行，再进程/网络/账号/服务/安全配置/受限文件/软件包，汇合可信基线/9规则/调度/JSON Markdown报告。P0工具独立Adapter先osquery/Lynis；AI与Skills在确定性链路之后；MCP/Runner/RBAC及Web按WP6/7推进。

真实企业试点资产、发行版/权限/指纹/窗口/外发政策尚未提供，阻止相应运行/部署验收，不阻止后续离线实现。没有运行SSH/恶意样本/外部模型，没有自动处置；无命中不能保证绝对无木马。工作区保留所有原未跟踪用户文件与本轮成果，build产物默认gitignored。
