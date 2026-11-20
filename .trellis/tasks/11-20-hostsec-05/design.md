# HOSTSEC-05 技术设计

状态：本任务交付PARTIAL；以下新增契约与测试为计划。当前有效目录和依赖方向遵循REPOSITORY-LAYOUT及ADR-008。

## 当前能力与未来适配

已有Run(ctx,args,stdout,stderr)及signal.NotifyContext、version/doctor/assets/plan。保留当前命令与错误输出；对单纯结构迁移逐字不变。当前无存储/扫描器，不能为满足help列表新增会返回成功的scan/status/findings/evidence/report/mcp占位。未来用例实现后再扩help并加进程测试。

## 调用与错误契约

CLI只解析已知类型并调用资产/计划/未来扫描应用用例，业务授权不能只做在handler。稳定诊断对象沿用level/code/message；输入相关错误用固定安全说明，不包含原始配置、完整argv、认证引用解析结果或模型正文。stdout只有一个请求结果，日志/错误在stderr；帮助exit0，参数/配置/授权exit2，运行/能力不可用/输出失败/取消exit1。取消原因用CANCELLED、deadline用TIMEOUT，不由shell信号编码假装规则FAIL。

新timeout若作用于本地操作，解析为正time.Duration并由context.WithTimeout传递；总deadline与各模块deadline取较短者。max-concurrency必须正数且不超过受控策略，离线计划即使接收预算也保持limits.enforced=false。统一参数以明确命令局部FlagSet实现，不能把未经使用的global flag接受后静默忽略。参数表、输出Schema和help在接入切片一并更新，现有v1不静默增加required字段。

Run使用writer错误返回，不panic/os.Exit；只有main决定进程退出。错误格式化和schema编码失败不能再次把完整业务对象写stderr。ctx在业务处理、序列化前和有限循环中检查；阻塞I/O要由支持context的用例限制，不能只在顶层读一次ctx。

## 信号与未来状态

生产入口保留signal.NotifyContext，清理函数在os.Exit前显式调用。进程级验证使用测试辅助程序和受控慢用例，不要求创建真实scan或睡眠竞态测试。执行器未来负责停止子进程/固化证据/终态，CLI不得自行kill任意进程或删结果。status/retry/resume的持久查询接口归15/36，05只确定输出/错误适配及接入测试协议；完整运行生命周期验收需36实链补证据。

## 兼容、回滚与证据

命令适配与业务变更分别提交/审查；保留既有命令输出和error codes；未接通用例的命令从help撤除而非成功降级。

完成证据：docs/05-testing/evidence/hostsec-05：逐命令契约表、signal/timeout进程日志和退出码、writer故障、注入与敏感值canary结果。 对应日志必须包含命令、工作目录、实际退出、输入/源码版本与验证范围；没有结果不写PASS。
