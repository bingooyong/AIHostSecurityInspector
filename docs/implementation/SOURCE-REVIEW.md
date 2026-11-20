# V1.0 逐文件一致性审查

日期 2026-11-20；设计审查 IMPLEMENTED，产品实现状态另列。原文件字节由 v1-source-manifest.json 固定。

| 来源 | 复核结论 / 修订 |
|---|---|
| README | 方案不等于完成；MVP 必须全部六项达标；企业环境未知继续保留 |
| 00 总体建设 | HTML 从首期移至后续；osquery/Lynis 属 P0 Adapter 路线，但不阻止原生端到端链路；ADR-001 |
| 01 需求 | JSON 导入与 incident-response 纳入；所有 Finding 必须真实 evidence_refs，缺证据以 RuleResult UNKNOWN 表达，不能无证据 Finding；ADR-002 |
| 02 架构 | 原始证据先本地落盘，标准化用于规则，脱敏视图单独给 AI；首切片无数据库；ADR-003 |
| 03 SDD | 状态机允许任何活动阶段取消/超时；取消保留证据，失败不转 PASS；SSH 使用固定部署 Collector，不上传任意脚本；ADR-004 |
| 04 规则目录 | quick 统一包含 security_config；变化规则必须有可信基线，无基线 UNKNOWN；隐藏进程/rootkit 仅交叉视图异常，不能承诺完全检测 |
| 05 接口 | 首切片只实现帮助/version/doctor/assets validate/list/plan；scan 等命令尚不可用，非成功占位；HTML/PDF/MCP 后续 |
| 06 AI | 原图将脱敏置于规则之前，修正为原始→标准化→确定性规则→最小脱敏视图→AI；AI 默认禁用；引用验证还要求同 host/scan 与成功证据；ADR-005 |
| 07 安全 | READ_ONLY 不等于绝对零写入：证据输出、工具日志、SSH 审计和 atime 是允许/须披露的副作用；禁止主机安全配置/账号/服务等变更；ADR-006 |
| 08 路线/验收 | 用户本轮 WP0 为仓库工程基线，真实资产盘点留在试点 gate；AC 以真实执行证据验收，交叉编译不是双架构运行验收 |
| 09 运维 | 本轮仅本地离线 CLI；远程安装、凭据、生产窗口、外发审批尚未准备 |
| 10 执行任务书 | 本轮用户路径 docs/00-project-inventory.md 为权威；Windows 只保留设计，无空目录模拟；首切片不装扫描器 |
| 11 参考资料 | 官方资料重新调研，不按链接存在声称兼容；YARA 维护模式、版本化许可证见工具调研 |
| MVP 清单 | 保留未勾选源清单；当前状态单独见 MVP-PLAN/执行报告 |
| examples/hosts | RFC 5737 地址仅示例；严格版规范独立于源样例，不静默接受源中未实现字段 |
| examples/policy | 缺 IR，deep 未继承全部 standard；新增四种固定 Profile 与明确安全限额，资源限额真正执行留待调度器 |
| schemas/scan-result | 草案 evidence 缺 host_id/scan_id/collector_version/rule_version/完整性；新版结果契约独立版本化，缺哈希不能伪造 64 位值；ADR-002 |
| .agents Skill | 源模板已读；scan 未实现前不得作为可运行巡检能力安装 |
| plugin/README | 尚无实际 MCP 服务，模板不可直接启用 |
| plugin/.codex-plugin/plugin.json | 版本 1.0.0 是源示例，不代表当前产品版本 |
| plugin/.mcp.json.example | 占位 URL 不部署、不替换为猜测端点 |
| plugin/skills Skill | 与 .agents 源模板同摘要；MVP-6 后验证 CLI/Agent 契约 |

原设计保留，修订、影响与对应测试以 ADR 和 SDD 为准。未发现阻止离线首切片的冲突；真实远程巡检仍有授权、环境、审批阻塞。
