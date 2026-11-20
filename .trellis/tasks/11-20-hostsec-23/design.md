# HOSTSEC-23 设计

范围：仅限批准路径/签名库时效/禁止删除移动复制。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/tools/clamav/。

安全重点：压缩炸弹/内存IO。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
