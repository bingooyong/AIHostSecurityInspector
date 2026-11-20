# HOSTSEC-19 设计

范围：用户要求17项、覆盖率分母、未覆盖、人工复核与证据索引。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/report/。

安全重点：未扫描显示安全。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
