# HOSTSEC-29 实施计划

1. 核对前置任务 HOSTSEC-28, HOSTSEC-19, HOSTSEC-36 的完成证据。
2. 加载输入与对应SDD，冻结本任务接口、文件所有权和风险。
3. 分小步实现：只调用已实现CLI，授权/计划/报告流程；无任意shell能力。
4. 自动化：Agent合约/参数注入/恶意证据测试；必要静态检查和安全回归。
5. 独立代码审计；重跑受影响测试，更新风险、ADR、PRD/SDD/README与状态。
6. 将日志/产物摘要写 completion_evidence 后才标 IMPLEMENTED。

并行：仅在前置任务验收且文件所有权互斥后并行；集成与状态变更串行。执行前未完成的技术选型和环境能力必须先验证；本规划不授权真实生产连接。

产品Skill分发源位于integrations/skills/，安装适配可写对应客户端约定目录；开发工作流既有.agents/.claude文件不得覆盖。
