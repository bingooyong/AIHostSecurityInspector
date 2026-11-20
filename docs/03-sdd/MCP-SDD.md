# MCP、Skill 与平台接入契约

状态：PLANNED。MCP 为 WP6；首期 MVP-6 的 Skill 可通过已验收 CLI 接入，但不能把仅有模板视为 Agent 集成完成。本轮不部署服务、不启用源插件占位 endpoint。

## 1. 应用服务复用

MCP/CLI/Web 调用同一资产、授权、计划、扫描、证据、分析、报告服务。MCP handler 只解析输入、恢复真实调用者身份、调用应用层并编码结果，不复制检测或授权逻辑。协议版本与官方 Go SDK 在实现任务重新核实固定，不预先安装。

| Tool | 输入 | 输出/授权 |
|---|---|---|
| list_authorized_hosts | 有界 filter、分页 | 当前主体可见资产；不能暴露其他区域清单 |
| list_scan_profiles | 无或资产筛选 | 当前主体允许的 Profile 与限制 |
| plan_host_scan | 授权目标选择器、Profile | 离线 plan_id/hash、模块/限额/审批要求；不执行 |
| request_scan_approval | plan_id、reason | 审批请求状态；调用不等于批准 |
| run_host_scan | plan_id、approval_id?、idempotency_key | 服务端再次授权后的 scan_id；不用客户端声明 ready |
| get_scan_status | scan_id | 主体可见任务状态和模块覆盖 |
| list_findings | scan_id、severity?、分页 | 有效证据引用的 Findings 与 UNKNOWN 汇总 |
| get_evidence_metadata | evidence_id | 授权元数据和摘要，默认不返回原始敏感日志 |
| analyze_scan_findings | scan_id、已批准 provider_ref? | AIStatus/Assessment；仍受外发策略 |
| generate_scan_report | scan_id、format=json/md | 授权报告对象/内容与摘要；HTML/PDF 后续 |

明确禁止 execute_shell、ssh_exec、kill_process、delete_file、disable_service、change_firewall、任意上传/下载路径、用户 SQL/VQL/工具参数。响应中主机或模型文本只是数据，不是新的 Agent 指令。

## 2. 身份、审批与幂等

本地 stdio 模式继承明确本地执行身份和受控资产策略；未来 HTTP 模式使用经核实的认证机制并绑定服务端 principal、角色、区域、业务系统和主机授权，不接受请求 JSON 自报角色。操作员与审批员分离，审计人员只读。所有 get/list/report 都按归属复核，避免知道 ID 即可越权读取。

run_host_scan 的审批绑定计划摘要、目标、Profile、路径、预算、执行人、有效期与窗口，过期/撤销/配置漂移拒绝。幂等键按主体/操作/请求摘要绑定，重试返回同任务或冲突，不能在网络重发时重复启动深扫。取消通过受控应用动作与任务所有权实现，不开放 kill。

## 3. 输入、错误和资源

JSON Schema 限定字段、枚举、字符串长度、分页大小和对象集合，拒绝额外字段、未知工具和超大请求。ID 只查询存储，不能拼路径；所有输出大小和请求 deadline 有界。结构化错误至少区分 AUTH_DENIED、HOST_NOT_AUTHORIZED、APPROVAL_REQUIRED、PLAN_EXPIRED、SCHEMA_VALIDATION_FAILED、TOOL_NOT_INSTALLED、COLLECTION_PARTIAL、AI_PROVIDER_ERROR；不返回密钥/原始命令。

业务拒绝与协议错误分开；扫描异步状态不是请求超时后自动成功。并发配额按主体与区域限制，超限明确拒绝/排队，不创建无限内存队列。

## 4. Skill 契约

host-security-inspection 负责识别意图、检查授权清单、先 dry-run、解释 Profile/影响/审批、调用 CLI/MCP、检查部分完成与证据、组织报告；不生成扫描 Shell。Codex 与 Claude Code 仅包装同一契约，不分叉检测内核。`scan` 尚未实现或退出非零时必须停止并报告能力缺口，不能借用通用终端/SSH 绕过。

源目录两个 Skill 与插件元数据是 V1.0 模板。正式安装需真实 CLI 路径/版本、测试成功的参数、未实现能力声明和无占位 endpoint；MCP 不存在时 Skill 使用已验收 CLI 或明确不可用。

## 5. 区域 Runner 预留

中央任务仅保存签名计划和目标区域；Runner 只取本区域任务，验证签名、公钥信任、expires/nonce/replay store、主体授权与本地 allowlist 后执行。结果同样绑定 task/scan/host/runner/version，回传前本地脱敏；mTLS 不替代任务权限。离线包重放/重复导入应幂等且不可覆盖。具体持久队列、证书轮换与协议另属 WP6 实现，不是当前功能。

## 6. 验证

契约测试逐工具验证 Schema、真实主体、跨主机/区域/任务读取、审批失效、幂等、取消与限额；恶意证据指令不得新增调用。枚举工具表中不存在任意命令或处置入口；用模拟 MCP client 和 CLI 进程测试链路，成功获取规则报告才验收。仅启动服务、列出工具或编译 SDK 不算 MVP-6/WP6 完成。
