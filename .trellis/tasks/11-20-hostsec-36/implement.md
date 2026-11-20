# HOSTSEC-36 实施计划

1. 核对前置任务 HOSTSEC-07, HOSTSEC-08, HOSTSEC-09, HOSTSEC-10, HOSTSEC-11, HOSTSEC-12, HOSTSEC-13, HOSTSEC-14, HOSTSEC-16, HOSTSEC-17, HOSTSEC-32A, HOSTSEC-37, HOSTSEC-38 的完成证据。
2. 加载输入与对应SDD，冻结本任务接口、文件所有权和风险。
3. 分小步实现：模块隔离超时/取消/压力停止/限额，计划授权复核，失败不变PASS。
4. 自动化：VM端到端、signal、重试attempt、资源压力/中断；必要静态检查和安全回归。
5. 独立代码审计；重跑受影响测试，更新风险、ADR、PRD/SDD/README与状态。
6. 将日志/产物摘要写 completion_evidence 后才标 IMPLEMENTED。

并行：仅在前置任务验收且文件所有权互斥后并行；集成与状态变更串行。执行前未完成的技术选型和环境能力必须先验证；本规划不授权真实生产连接。
