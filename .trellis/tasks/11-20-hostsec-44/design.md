# HOSTSEC-44 设计

范围：审批基线、host identity、SSH key/config/服务差异、历史attempt。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/baseline/。

安全重点：攻击后快照被当可信基线。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
