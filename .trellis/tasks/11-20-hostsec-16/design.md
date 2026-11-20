# HOSTSEC-16 设计

范围：原始/标准化双摘要，缺原始明确状态，不伪造摘要。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/evidence/manifest.go。

安全重点：hash不能证明来源真实性。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
