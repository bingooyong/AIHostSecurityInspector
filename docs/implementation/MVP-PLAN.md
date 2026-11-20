# 首期MVP实施计划

日期2026-11-20；本轮只完成基线与MVP-1首切片。首期产品六项全部满足才交付。

| MVP | 目标 / 任务 | 当前状态 | 退出条件 |
|---|---|---|---|
| 1 | 03–07/32A/42：CLI/授权/YAML/JSON/Profile/Schema/dry-run | PARTIAL（首切片执行后据日志更新） | 可执行计划/审批/生命周期与全部契约验证，非仅version |
| 2 | 08–14/37/38：Linux系统/进程/网络/账号/服务/持久化/安全配置 | PLANNED | 测试Linux x86_64+ARM64真实运行、权限/竞态/资源记录 |
| 3 | 17/18/44：9规则正反例+可信基线 | PLANNED | 各规则正反/UNKNOWN/N/A，缺基线不造变化 |
| 4 | 15/16/19/36：状态/证据/hash/JSON/Markdown/覆盖 | PLANNED | 端到端链路且每Finding有效引用，完整性负例，17项报告 |
| 5 | 25–28：OpenAI/兼容/本地/脱敏/结构化/ref/降级 | PLANNED | 本地fake Provider故障和注入测试，真实外发需单独政策审批 |
| 6 | 29：Codex/Claude可调用Skill | PLANNED | 只调用已实现命令、授权/注入/无Shell合约；已有源模板不算交付 |

## 首切片验收

03A以资产→授权选择→四Profile离线计划→schema验证为真实垂直链路，无执行器。资产变更差异、可配置策略、审批验证、扫描/断点/失败重试尚未实现，不因首切片通过关闭完整03–07。CLI只能列出实际命令；无scan不是假扫描。

## 里程碑

G0：来源/基线/48节点DAG/接口/安全审查无离线阻塞。G1：03A运行和负例/Schema/本地CI命令通过。G2：原生Linux采集+证据+规则+报告端到端且最小权限副作用审查。G3：可选AI和Skill、完整MVP AC。G4：后续MCP/Runner/RBAC签名隔离再进入Web。

专业工具20/21优先评估和Adapter，其他按具体环境推进；缺工具/旧情报覆盖不足，不凭AI补全。所有gate要更新PRD/SDD/ADR/风险/README/状态和证据。企业资产/指纹/运行环境/窗口/外发待提供是运行部署阻塞，不是离线实现阻塞。

## 目录与滚动细化修订

ADR-008把Go工程迁至backend，frontend/integrations作为后续独立工程边界；CLI业务范围不变。WP1近期任务按WP1-DETAILED-PLAN推进，迁移与AGENTS/spec落地不等于MVP整体或完整03/42已交付。
