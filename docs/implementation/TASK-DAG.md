# HostSec WP0–WP7 任务 DAG

机器权威：task-dag.json；Trellis任务目录逐项保存PRD/设计/执行计划及上下文。父子树不等同依赖。每项输入、输出、范围、验收、测试、风险、并行条件与完成证据均在JSON中。以下阶段须服从跨阶段前置，允许证据/基线/审批提前完成。

| 任务 | 阶段 | 交付 | 前置 |
|---|---|---|---|
| HOSTSEC-00 | WP0 | 仓库与 Trellis 盘点 | 无 |
| HOSTSEC-01 | WP0 | 需求与架构基线 | HOSTSEC-00 |
| HOSTSEC-02 | WP0 | 威胁模型与数据边界 | HOSTSEC-01 |
| HOSTSEC-03A | WP1 | 离线授权计划首个垂直切片 | HOSTSEC-00, HOSTSEC-01, HOSTSEC-02 |
| HOSTSEC-03 | WP1 | Go 工程构建与发布骨架 | HOSTSEC-03A |
| HOSTSEC-04 | WP1 | 完整领域模型与版本化Schema | HOSTSEC-03A |
| HOSTSEC-05 | WP1 | CLI生命周期与输出契约 | HOSTSEC-03, HOSTSEC-04 |
| HOSTSEC-06 | WP1 | 资产授权和治理 | HOSTSEC-05 |
| HOSTSEC-07 | WP1 | 可执行计划与策略约束 | HOSTSEC-06, HOSTSEC-32A |
| HOSTSEC-08 | WP2 | Linux身份与系统采集 | HOSTSEC-04 |
| HOSTSEC-09 | WP2 | Linux进程采集 | HOSTSEC-08 |
| HOSTSEC-10 | WP2 | Linux本机网络采集 | HOSTSEC-08 |
| HOSTSEC-11 | WP2 | Linux账号权限采集 | HOSTSEC-08 |
| HOSTSEC-12 | WP2 | 服务与持久化采集 | HOSTSEC-08 |
| HOSTSEC-13 | WP2 | 安全配置采集 | HOSTSEC-08 |
| HOSTSEC-14 | WP2 | SSH固定Collector Transport | HOSTSEC-08, HOSTSEC-32A |
| HOSTSEC-15 | WP3 | 本地SQLite和证据落盘 | HOSTSEC-04 |
| HOSTSEC-16 | WP3 | SHA256 Manifest完整性 | HOSTSEC-15 |
| HOSTSEC-17 | WP3 | 有限DSL YAML规则引擎 | HOSTSEC-18, HOSTSEC-44 |
| HOSTSEC-18 | WP3 | Finding与RuleResult模型 | HOSTSEC-04, HOSTSEC-16 |
| HOSTSEC-19 | WP3 | JSON Markdown报告 | HOSTSEC-17, HOSTSEC-16, HOSTSEC-36 |
| HOSTSEC-20 | WP4 | osquery Adapter | HOSTSEC-40, HOSTSEC-16 |
| HOSTSEC-21 | WP4 | Lynis Adapter | HOSTSEC-40, HOSTSEC-16 |
| HOSTSEC-22 | WP4 | OpenSCAP Adapter | HOSTSEC-40, HOSTSEC-16 |
| HOSTSEC-23 | WP4 | ClamAV Adapter | HOSTSEC-40, HOSTSEC-16 |
| HOSTSEC-24 | WP4 | YARA Adapter | HOSTSEC-40, HOSTSEC-16 |
| HOSTSEC-25 | WP5 | AI Provider抽象 | HOSTSEC-18, HOSTSEC-19 |
| HOSTSEC-26 | WP5 | AI最小脱敏视图 | HOSTSEC-25 |
| HOSTSEC-27 | WP5 | 结构化AI关联研判 | HOSTSEC-26, HOSTSEC-19 |
| HOSTSEC-28 | WP5 | AI证据引用验证 | HOSTSEC-27, HOSTSEC-16 |
| HOSTSEC-29 | WP5 | Codex Claude Skill接入 | HOSTSEC-28, HOSTSEC-19, HOSTSEC-36 |
| HOSTSEC-30 | WP6 | MCP标准业务工具 | HOSTSEC-29, HOSTSEC-32, HOSTSEC-45 |
| HOSTSEC-31 | WP6 | 区域Runner | HOSTSEC-30, HOSTSEC-41, HOSTSEC-32 |
| HOSTSEC-32 | WP6 | 平台审批与审计 | HOSTSEC-32A, HOSTSEC-19 |
| HOSTSEC-33 | WP7 | Go Web API | HOSTSEC-30, HOSTSEC-31, HOSTSEC-32, HOSTSEC-45 |
| HOSTSEC-34 | WP7 | React TS管理端 | HOSTSEC-33 |
| HOSTSEC-35 | WP7 | 风险整改与趋势 | HOSTSEC-34, HOSTSEC-44 |
| HOSTSEC-36 | WP3 | 调度状态机与端到端扫描 | HOSTSEC-07, HOSTSEC-08, HOSTSEC-09, HOSTSEC-10, HOSTSEC-11, HOSTSEC-12, HOSTSEC-13, HOSTSEC-14, HOSTSEC-16, HOSTSEC-17, HOSTSEC-32A, HOSTSEC-37, HOSTSEC-38 |
| HOSTSEC-37 | WP2 | 受限文件元数据采集 | HOSTSEC-08 |
| HOSTSEC-38 | WP2 | 软件包清单 | HOSTSEC-08 |
| HOSTSEC-39 | WP3 | 离线漏洞情报关联 | HOSTSEC-38, HOSTSEC-17 |
| HOSTSEC-40 | WP4 | 统一只读工具执行器 | HOSTSEC-04 |
| HOSTSEC-41 | WP6 | 离线结果包与来源验证 | HOSTSEC-16, HOSTSEC-19 |
| HOSTSEC-42 | WP1 | CI与供应链门禁 | HOSTSEC-03A |
| HOSTSEC-43 | WP5 | 首期MVP总体验收 | HOSTSEC-29, HOSTSEC-19, HOSTSEC-36, HOSTSEC-28, HOSTSEC-42, HOSTSEC-39 |
| HOSTSEC-44 | WP3 | 可信基线与扫描差异 | HOSTSEC-16, HOSTSEC-06 |
| HOSTSEC-45 | WP6 | 身份与区域RBAC | HOSTSEC-32 |

## 实施波次

1. WP0：00→01→02，设计/安全审查后03A离线首切片。
2. WP1：03/04、05→06；32A本地审批前置于07；42首切片CI，完整任务只在相应能力验证后关闭。
3. WP2 + WP3：08后采集09～13/37/38可按文件并行；15→16与采集并行，44→18→17；14 SSH在32A后验证；36汇合成扫描链路→19报告。不得等到WP6才给deep加审批。
4. WP4：40统一执行器后osquery/Lynis优先，其余按OS/许可/副作用/资源gate接入。工具不是原生链路的强制依赖；缺工具必须覆盖不足。
5. WP5：25→26→27→28→29；43待MVP1-6完整端到端与AC运行证据后验收。39漏洞的可信情报能力独立，不用AI临时造库。
6. WP6：32平台审批/45RBAC→30MCP；41离线来源验证；31区域Runner；不得暴露任意exec。
7. WP7：33→34→35，共用内核与权限。后续平台不是本轮实现。

## 完成协议

需求确认→设计→实现→自测→独立审计→验收。IMPLEMENTED需持久化日志/产物与成功判据；PARTIAL写明缺项；BLOCKED写确切外部阻塞；无实现的后续节点PLANNED。依赖失败不能自动越过。资源/授权敏感的集成和状态变更串行；只读调研与不共享文件的实现可并行。

HOSTSEC-32A 独立节点：依赖04/06，07/14/36必须等待其审批验收。详见JSON。

## 当前工程目录与近期细化

Go交付路径统一backend/（ADR-008），前端为frontend/，产品Agent接入材料为integrations/。实际Trellis包为backend，规范层为go。WP1的7个活动节点已有字段/状态/测试/回滚级详细计划，62项内部执行检查项见[WP1详细计划](WP1-DETAILED-PLAN.md)；这些检查项没有增加48个子任务记录。归档任务和bootstrap原始日志保留其历史时点，DAG的交付路径索引指向当前工程位置。
