# 主控设计

采用 docs/02-architecture、docs/03-sdd 和 ADR 作为权威修订设计，V1来源字节不变。离线首切片遵循 CLI-SDD。WP0-WP7父子任务按 task-dag.json 依赖调度，阶段号不是可忽略依赖的许可。证据、可信基线、审批前置于执行；AI和入口不获得执行内核权限。

当前目录权威：docs/02-architecture/REPOSITORY-LAYOUT.md；ADR-008取代旧根Go module方案。迁移与行为锁定见docs/implementation/LAYOUT-MIGRATION-PLAN.md。
