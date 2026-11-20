# HOSTSEC-17 设计

范围：9条MVP规则含required_evidence与PASS/FAIL/UNKNOWN/N/A；不执行代码。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：backend/internal/rules/, rules/。

安全重点：规则包供应链和假绿。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。
