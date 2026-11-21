# 本次运行分阶段实施计划

日期：2026-11-20。授权范围：按仓库已有 DAG/PRD 实现规划任务；不改安全模型；不连接真实企业主机；不合并 main；不派生额外 Cloud Agent。

## 依赖拓扑（权威：`docs/implementation/task-dag.json`）

已归档 IMPLEMENTED：HOSTSEC-00/01/02/03A。

可立即推进（前置已验收）：

1. HOSTSEC-04（领域/Schema/ExecutionIntent）← 03A
2. HOSTSEC-03 剩余（版本注入/可复现发布）← 03A，与 04 文件互斥可并行
3. HOSTSEC-42 本地门禁路径（不覆盖 layout-migration 历史证据）← 03A

04 之后：

4. HOSTSEC-05 CLI 生命周期 ← 03, 04
5. HOSTSEC-06 资产快照/差异/复核 ← 05
6. HOSTSEC-32A 本地审批 ← 04, 06
7. HOSTSEC-07 可执行计划/Preflight ← 06, 32A

WP2 采集（08–13/37/38）依赖 04；14 另依赖 32A。真实 SSH/企业身份/远端 CI 标 BLOCKED，不冒充。

WP3–WP7 与 HOSTSEC-43 仅在前置验收后进入。本次若无法可靠完成全部 48 节点，交付依赖顺序下通过测试的最长端到端切片，其余保持 PARTIAL/PLANNED/BLOCKED。

## 本切片完成协议

- 复用 03A 离线 CLI 与冻结 11 条行为；不把 `execution_ready=true` 或 `doctor.scan_ready=true` 在 Collector 未实现时打开。
- 测试只使用隔离 fixtures / 本开发环境；不扫描未授权主机。
- 证据写入 `docs/05-testing/evidence/hostsec-*` 新目录，不覆盖 bootstrap/layout-migration。
- 只有实现与验收均满足才把 `meta.delivery_status` 改为 IMPLEMENTED 并 archive。
