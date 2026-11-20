# HOSTSEC-28 设计

范围：每结论绑定同scan-host真实允许证据集合。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/analyzer/validate.go。

安全重点：存在ID但不支持结论。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
