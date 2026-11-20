# HOSTSEC-04 技术设计

状态：本任务交付PARTIAL；以下新增契约与测试为计划。当前有效目录和依赖方向遵循REPOSITORY-LAYOUT及ADR-008。

## 实体职责与包位置

backend/internal/domain只放纯数据值、验证和状态转换，不依赖CLI、文件系统、HTTP Provider、数据库或Linux syscall。现有asset.Host/Inventory与planner.Plan不能再复制成两套不一致模型；优先保留输入DTO，domain值显式转换/验证，若移动类型需以兼容适配保持当前序列化。关系校验接收只读Snapshot，不接受任意磁盘路径或SQL。

## 字段与状态收敛

Host/Inventory保持CLI-SDD的严格v1；补充OS/version/identity等字段必须通过独立版本或明确兼容扩展，不让unknown被当成已采集。执行意图最低包含schema_version、requester_principal、host_ids/identity_refs、asset_snapshot_hash、policy_id/version/hash、profile、modules/tools、paths/exclusions、limits、required_capabilities、valid_from/until、maintenance_window、mode=READ_ONLY。

ScanJob包含scan_id、requester、plan_hash、Profile、host_ids、各版本、created/started/completed、status、failure_reason、coverage；Attempt包含attempt_id、scan/host、retry_of、模块状态和起止时间。终态不可继续写入同attempt，重试追加新attempt。时间统一RFC3339 UTC、零/倒置时间拒绝，host collected_at和控制端received_at不互相冒充。

本轮目录/规划审查已修正文档已知枚举漂移，04实现前仍须逐项验证SDD与已有scan-result Schema一致。现有schema的collection_status包含success/partial/failed/not_available/not_applicable/timeout/cancelled，completeness为complete/partial/unavailable，integrity_status为verified/unverified/failed/unavailable；领域文档旧none或缺失值不得被代码静默采纳。顶层执行摘要若另含skipped，应显式映射而非伪造证据。冻结v1后不直接改写历史已生成结果，新增版本另列兼容适配。

RuleResult的outcome固定PASS/FAIL/UNKNOWN/NOT_APPLICABLE，独立于Finding.review_status和ScanJob.status。无适用性才N/A；工具缺失/权限/解析/无基线均UNKNOWN。Finding须同host/scan有效非空evidence_refs；Evidence记录module、collector/version、raw/normalized摘要与对象引用、collection/integrity/completeness；rule_version在RuleResult/Finding关联中记录，不让Collector伪称执行过规则。失败Evidence只能支撑采集失败事实，不能支持“未发现恶意/账号安全”。Assessment引用还限定为本次发给AI的证据集合，不接受severity覆盖。

## 纯函数契约

计划新增接口语义为ValidateSnapshot(snapshot)、ValidateFinding(finding, evidenceIndex)、ValidateAssessment(assessment, allowedEvidence)、CanTransition(from,to)、CanonicalExecutionIntent(intent)→bytes、HashExecutionIntent(intent)→SHA256。Go名称可在实现中按包职责精简，但输入/结果/错误语义必须在测试中固定。错误至少区分INVALID_ID、INVALID_STATE_TRANSITION、INVALID_TIMESTAMP、UNKNOWN_EVIDENCE、CROSS_SCOPE_REFERENCE、EVIDENCE_UNUSABLE、SCHEMA_VERSION_UNSUPPORTED；错误不回显原始敏感字段。

规范化意图不包含plan_id、展示文字、created_at接收时刻、approval或临时execution_ready标志；安全相关有效期/主体/目标身份/版本/路径/预算必须包含。采用明确结构化整数/字符串、禁止浮点/重复key/隐式省略、固定列表语义与排序规则，版本标记随摘要输入。32A依赖本契约测试输入，07依赖32A并不形成反向循环。具体canonicalization算法及golden必须在04实施设计审查冻结，未冻结不进入32A签名实现。

## 兼容、回滚与证据

实体和Schema分小步变更，保留当前v1 DTO及fixture；通过显式转换兼容旧版本，禁止覆盖已导出证据，回滚不删除历史结果。

完成证据：docs/05-testing/evidence/hostsec-04：字段/枚举对照、合法及负例fixture、摘要golden、同scope关系失败记录、依赖树、CLI兼容结果。 对应日志必须包含命令、工作目录、实际退出、输入/源码版本与验证范围；没有结果不写PASS。
