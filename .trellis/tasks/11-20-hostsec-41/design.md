# HOSTSEC-41 设计

范围：zstd/tar受限解包、签名、源身份、manifest验证和导入事务。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/bundle/。

安全重点：摘要可重算不等于来源可信。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
