# HOSTSEC-07 技术设计

状态：本任务交付PARTIAL；以下新增契约与测试为计划。当前有效目录和依赖方向遵循REPOSITORY-LAYOUT及ADR-008。

## 策略合同与所有权

policy包只解析和校验受控策略，planner只构建与复核计划；它们不得启动子进程、访问主机、读取模型响应或修改系统配置。配置源为固定本地路径/审批包，禁止扫描时从URL下载。策略最低字段为schema_version、policy_id/version、mode=READ_ONLY、allowed module/tool IDs、四Profile、timeout/concurrency/file/IO/pressure limits、paths/exclusions/mount exclusions、approval/maintenance规则和content_hash。首切片fixed catalog仍可作为安全默认，外部策略不支持字段必须拒绝。

## Profile与资源

quick含host_identity/process/network/account/service/persistence/security_config；standard累积并加package/vulnerability/baseline/approved targeted file；deep再加integrity/YARA/log analysis且审批/窗口强制，IR只取批准事件范围。任何策略都不能加入任意cmd/script/SQL或处置动作。module/tool ID与程序内受控注册表匹配，额外内容不能由Agent声明自动可信。

限额至少为scan/module/connect timeout、max_concurrency、max_files、max_file_size_bytes、max_total_bytes、recursion_depth、io_max_bytes_per_second、allowed/excluded_paths、excluded_mount_types、stop_on_resource_pressure、压力阈值和maintenance_window。数值单位固定bytes/seconds，均有上限且不接受无限/负数；预算具体默认以已有安全默认和测试资源评审收敛，不能用机器性能猜值。请求只能收紧策略，放宽需新策略审批；空allowlist不等于允许所有目录。路径清洗只做预检查，真实symlink/mount/TOCTOU由37执行时验证。

## 计划和审批去耦

04先交付ExecutionIntent规范化/hash；32A验证该纯typed intent和签名审批；07再构建相同intent并集成验证。故07依赖32A而32A不依赖07实现，不增加环。plan_id是展示/查找ID，plan_hash才绑定安全内容。Plan包含asset_snapshot_hash、policy hash、requester、scope、versions、validity、modules/capabilities、limits、estimated_impact、approval_required、limitations；展示字段不参加签名，安全字段不能漏签。旧03A plan输出v1若无新字段用兼容适配或新版本，不默认为已签名执行计划。

## Preflight的输入与结果

ValidateForExecution(ctx,plan,currentSnapshot,currentPolicy,principal,verifiedApproval,capabilitySnapshot,resourceState,clock)返回允许/拒绝及有界原因列表；不接受客户端自报verified或ready。对输入快照按计划hash重算，复核当前授权/Profile/区域/身份、签名信任/撤销/过期/nonce、窗口、能力/内容版本、磁盘/CPU/IO状态。缺权限/工具/签名/身份/资源遥测应拒绝或标不可执行，决不能PASS。

验证结果不能替代运行守卫；调度器36在开跑前按同一事务/租约消费审批并复核，在运行期间实施预算/取消/压力停止。现阶段不输出execution_ready=true且不开放scan。错误至少为POLICY_INVALID/UNSUPPORTED、PLAN_INVALID/EXPIRED/CHANGED、AUTH_DENIED、APPROVAL_*、HOST_IDENTITY_*、CAPABILITY_UNAVAILABLE、RESOURCE_PRESSURE、WINDOW_CLOSED、CANCELLED/TIMEOUT。拒绝不扩范围、不自动换Profile/目标/工具。

## 兼容、回滚与证据

策略/计划格式版本化且保留只读导入，不覆盖已签审批/旧计划；新增策略失败不回退到更宽松默认，回滚不执行旧过期任务。

完成证据：docs/05-testing/evidence/hostsec-07：policy/intent/hash golden、四Profile及逐字段篡改矩阵、审批与Preflight拒绝、未实现守卫说明。 对应日志必须包含命令、工作目录、实际退出、输入/源码版本与验证范围；没有结果不写PASS。
