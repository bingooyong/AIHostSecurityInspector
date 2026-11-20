# HOSTSEC-12 设计

范围：systemd/timers/cron/at/rc/profile/启动项/模块。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/collector/linux/persistence.go。

安全重点：恶意服务描述注入。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
