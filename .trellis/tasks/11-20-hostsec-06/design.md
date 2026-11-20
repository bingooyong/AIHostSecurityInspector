# HOSTSEC-06 技术设计

状态：本任务交付PARTIAL；以下新增契约与测试为计划。当前有效目录和依赖方向遵循REPOSITORY-LAYOUT及ADR-008。

## 输入与模块职责

asset负责有界单文档解析、结构/关系校验和不可变Snapshot；authorization负责以当前可信主体/策略对Snapshot目标作决策，不把CLI flag当权限来源。当前v1字段、1MiB/1000host、16层、显式null拒绝及strict host key保持；增加distribution/os_version、维护窗口或标签选择器前明确Schema版本与兼容方式，不把V1原示例不支持字段静默吞掉。

Snapshot语义为{inventory, schema_version, canonicalization_version, content_hash, loaded_at}。content_hash只覆盖规范化语义清单，loaded_at和源文件路径不参与安全摘要；authorized、allowed_profiles、addresses、zone、环境、connection引用、组成员都必须参与。排序/去重规则应复用04规范化工具的适用部分，duplicate在输入阶段拒绝而非悄悄去重。用深拷贝/不可变API避免caller修改已hash的slices/maps；已hash对象之后不再接受原指针任意写入。

## 领域用例

计划新增LoadSnapshot(ctx,path)、SelectAuthorized(snapshot,selector,profile,principal)、CompareSnapshots(before,after)、RevalidateTargets(current,plannedScope)用例。选择器仍仅registered host ID或group，标签目前用于治理展示；若增加tag选择必须显式审批其授权行为和规模界限。Compare输出added_host_ids、removed_host_ids、changed_hosts[{host_id,changed_fields,before_hash,after_hash}]，不把auth_ref对应秘密解析出来；组变化单列，排序稳定。

RevalidateTargets比对请求主体/host_id/资产版本、授权、Profile、安全域、认证/known_hosts引用和已绑定主机身份；任一变更产生ASSET_CHANGED或AUTH_DENIED，不自动用新地址继续旧计划。拒绝回显资产原文或凭据。真实SSH host identity来源为14，系统身份来源为08；两者缺失的运行任务应阻断或显式不完整，不能用hostname/IP自身证明相同。

## 文件与平台边界

读取继续拒绝非普通文件/符号链接，并对实际打开描述符做大小/权限/读取边界检查；路径只选择本地资产文件，不构成任意主机文件读取接口。读取后计算快照；执行前再读比对不能消除全部TOCTOU，最终绑定固定内存目标/身份并由transport核验。平台45接入服务端RBAC时替换principal来源，本地可写清单不构成多租户授权。

错误最少分INVALID_ASSETS、HOST_NOT_REGISTERED、HOST_NOT_AUTHORIZED、PROFILE_NOT_AUTHORIZED、ASSET_CHANGED、HOST_IDENTITY_UNKNOWN/MISMATCH、CANCELLED/TIMEOUT；CLI安全映射由05管理。单元用静态或内存fixture，不查询DNS或连接地址。

## 兼容、回滚与证据

快照/差异新增API与现有解析分离，保留v1输入及golden；不写回资产文件、不自动撤销主机或改密钥。回滚索引/适配不覆盖来源文件或旧计划记录。

完成证据：docs/05-testing/evidence/hostsec-06：Snapshot摘要golden、逐字段变动矩阵、混合组/撤权拒绝、diff fixture、文件与identity未知负例及CLI兼容。 对应日志必须包含命令、工作目录、实际退出、输入/源码版本与验证范围；没有结果不写PASS。
