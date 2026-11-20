# HOSTSEC-43 设计

范围：MVP1-6全部与AC01-15逐项真实证据，Linux双架构运行。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：docs/05-testing/ACCEPTANCE-RESULTS.md。

安全重点：把交叉编译/fixture当运行验收。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
