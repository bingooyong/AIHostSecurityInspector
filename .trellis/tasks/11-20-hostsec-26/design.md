# HOSTSEC-26 设计

范围：字段白名单、凭据PII脱敏、长度上限、默认本地。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/analyzer/redaction/。

安全重点：自由文本隐蔽秘密。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
