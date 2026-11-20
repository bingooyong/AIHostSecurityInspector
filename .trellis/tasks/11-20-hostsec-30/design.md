# HOSTSEC-30 设计

范围：10业务工具，调用者身份/权限过滤，资源上限。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/mcp/。

安全重点：会话身份与主机授权脱节。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
