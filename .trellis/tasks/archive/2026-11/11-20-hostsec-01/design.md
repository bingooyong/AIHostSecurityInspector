# HOSTSEC-01 设计

范围：六项MVP与后续范围、来源差异和ADR可追溯。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：docs/01-product/PRD.md, docs/02-architecture/SYSTEM-ARCHITECTURE.md, docs/implementation/SOURCE-REVIEW.md。

安全重点：文档漂移和范围膨胀。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
