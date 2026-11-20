# HOSTSEC-24 设计

范围：审查规则、固定版本、文件范围与timeout；YARA-X另评估。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/tools/yara/。

安全重点：上游维护模式与规则资源耗尽。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
