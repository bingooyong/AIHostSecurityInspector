# HOSTSEC-17 实施计划

1. 核对前置任务 HOSTSEC-18, HOSTSEC-44 的完成证据。
2. 加载输入与对应SDD，冻结本任务接口、文件所有权和风险。
3. 分小步实现：9条MVP规则含required_evidence与PASS/FAIL/UNKNOWN/N/A；不执行代码。
4. 自动化：每规则正反/缺证据/缺基线/非法DSL/资源界限；必要静态检查和安全回归。
5. 独立代码审计；重跑受影响测试，更新风险、ADR、PRD/SDD/README与状态。
6. 将日志/产物摘要写 completion_evidence 后才标 IMPLEMENTED。

并行：仅在前置任务验收且文件所有权互斥后并行；集成与状态变更串行。执行前未完成的技术选型和环境能力必须先验证；本规划不授权真实生产连接。
