# 验收标准

AC01–15保留用户原意。尚未执行的项目PLANNED；局部证明PARTIAL，不能推断完整验收。

| AC | 要求 | 任务 | 真实证据判据 | 初始状态 |
|---|---|---|---|---|
| AC-01 | CLI可运行 | 03A/05 | 本地二进制version/assets/plan进程测试 | PLANNED |
| AC-02 | 未授权主机无法扫描 | 06/07/45 | 首切片仅证明规划拒绝，扫描授权待执行器验证 | PLANNED |
| AC-03 | dry-run完整计划 | 07 | 03A离线模块/资源/审批，执行前计划待验证 | PLANNED |
| AC-04 | Linux真实系统采集 | 08/43 | 双架构测试VM采集与人工核对 | PLANNED |
| AC-05 | 结构化进程信息 | 09/43 | PID/PPID/path/user/hash且EACCES/竞态 | PLANNED |
| AC-06 | 端口进程关联 | 10/43 | IPv4/6监听inode-PID与缺权限 | PLANNED |
| AC-07 | 规则正反例 | 17/44 | 九条规则正反/UNKNOWN/N/A | PLANNED |
| AC-08 | Finding证据有效 | 16/18 | 同scan-host真实引用，缺失拒绝 | PLANNED |
| AC-09 | SHA256完整性 | 16/41 | 修改字节/manifest/来源签名负例 | PLANNED |
| AC-10 | AI引用不可伪造 | 28 | 虚构/跨scan-host/无依据引用拒绝 | PLANNED |
| AC-11 | AI故障报告降级 | 19/27 | 本地故障Provider仍有确定性报告 | PLANNED |
| AC-12 | 只读无意外系统变更 | 14/36/40 | 隔离VM前后文件/服务/配置快照及允许副作用 | PLANNED |
| AC-13 | 不存在任意Shell入口 | 03A/14/29/30/40 | AST/CLI注入/Skill/MCP工具白名单与实际执行路径审计 | PLANNED |
| AC-14 | 文档与代码一致 | 01/42/43 | 状态/链接/Schema/需求AC和产物检查 | PLANNED |
| AC-15 | 可独立扩展 | 04/17/25/40 | 新增无害Collector/Rule/Analyzer符合合约，无CLI核心改写 | PLANNED |

MVP总验收另需全部六项、Linux双架构运行矩阵/资源/只读副作用证据；没有真实VM运行记录就不能关闭43。
