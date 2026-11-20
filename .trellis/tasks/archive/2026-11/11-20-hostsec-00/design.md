# HOSTSEC-00 设计

范围：保留既有文件，核对环境和22份来源。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：docs/00-project-inventory.md, docs/implementation/v1-source-manifest.json。

安全重点：覆盖用户未跟踪文件。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
