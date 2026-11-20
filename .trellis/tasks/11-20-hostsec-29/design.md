# HOSTSEC-29 设计

范围：只调用已实现CLI，授权/计划/报告流程；无任意shell能力。依赖边界见 docs/implementation/task-dag.json 和对应 docs/03-sdd/。

输出文件：.agents/skills/host-security-inspection/SKILL.md, .claude/skills/host-security-inspection/SKILL.md。

安全重点：Skill模板误报能力已交付。所有未来任务当前为设计契约，不能声称代码存在。优先使用同一领域应用服务，错误显式分类，缺证据 UNKNOWN，默认只读。回滚只移除本任务新增代码/配置，保留历史证据。

产品Skill分发源位于integrations/skills/，安装适配可写对应客户端约定目录；开发工作流既有.agents/.claude文件不得覆盖。
