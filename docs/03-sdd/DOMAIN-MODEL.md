# 领域模型与状态契约

设计基线 0.1，2026-11-20。资产/离线计划已实现。2026-11-20 WP1 切片在 `backend/internal/domain` 增加了纯数据 ExecutionIntent/ScanJob/Attempt/Evidence/Finding/Assessment 校验与规范化摘要；这不是采集运行或数据库落地。采集、SQLite、规则求值仍为 PLANNED。

## 1. 身份与版本

ID 使用有界安全标识符，不能解释为文件路径或命令。host_id 是稳定业务标识，不用 IP 代替；主机身份指纹单独记录，身份漂移暂停执行并人工确认。扫描产生 scan_id，每次重试有独立 attempt_id，证据 ID 全局唯一。时间用 RFC 3339 UTC；来源主机时钟与控制端接收时间分别保存，时钟偏差记入限制。

schema_version、collector_version、policy_version、rule_bundle_version 独立版本化。输入拒绝未知核心字段；后续版本通过明确兼容适配导入，不把较新字段静默丢弃。

## 2. 核心实体

| 实体 | 最低字段 | 不变量 |
|---|---|---|
| Host | host_id、hostname、addresses、platform、distribution/os_version、architecture、zone、environment、business_system、owner、criticality、authorized、allowed_profiles、labels、connection refs | OS/version 未知必须显式未知；首切片严格子集见 CLI-SDD；密钥仅引用 |
| ScanPlan | plan_id/hash、host_ids、Profile、modules/tools、paths/exclusions、limits、approval_required、policy_version、requester、expires_at | 完整目标集合授权；离线计划不等于执行许可；首切片 execution_ready=false |
| Approval | approval_id、plan_hash、host_ids、requester、approver、valid_from/until、window、decision、revoked_at | deep/IR 执行时有效，审批人与请求人分离；绑定内容变化需重审 |
| ScanJob | scan_id、requester、host_ids、Profile、plan_hash、policy/rule/collector versions、status、created/started/completed_at、coverage、failure_reason | 不覆盖历史 attempt；任务完成与安全 PASS 是不同维度 |
| ScanAttempt | attempt_id、scan_id、host_id、start/end、transport、module outcomes、status、retry_of | 仅失败/未完成模块可按策略重试，新证据不得覆盖旧对象 |
| Evidence | evidence_id、scan_id、host_id、attempt_id、category、module、collector name/version、collected/received_at、raw_summary/ref/hash、normalized/ref/hash、collection_status、completeness、integrity_status | 对象实际存在且摘要验证；采集失败不能伪造成功数据；规则版本在关联求值记录 |
| RuleResult | rule_id/version、host_id/scan_id、outcome、evidence_refs、reason_code、missing_evidence、baseline_ref | 四值判断；缺证据为 UNKNOWN；不因不支持而 PASS |
| Finding | finding_id、host_id/scan_id、rule_id/version、category、severity、confidence、title、description、evidence_refs、rationale、remediation_guidance、review_status、first/last_seen | 至少一个同主机同扫描、完整性有效且足以支撑结论的证据；AI 不能覆盖 severity |
| Assessment | assessment_id、scan_id/host_id、provider/model/prompt version、input IDs/hash、output/hash、overall_assessment、risk_level、confidence、facts、inferences、evidence_refs、missing_evidence、actions、limitations、human_review | 只接受脱敏视图；引用限定本次输入集合；原始模型响应不自动成为事实 |
| AuditEvent | event_id、actor、action、target refs、timestamp、decision/outcome、request_id、previous_hash | 不保存凭据或原始敏感负载；链式哈希非外部认证证明 |

Finding 的 `review_status` 采用 new/needs_more_evidence/confirmed/false_positive/accepted_risk/in_progress/fixed/reopened；规则 outcome 不复用此字段。高危异常仍是待复核发现，不能仅凭 severity 判定“木马确诊”。

## 3. 状态机

ScanJob：CREATED → VALIDATING → WAITING_APPROVAL 或 QUEUED；验证拒绝为 REJECTED。QUEUED → RUNNING → COLLECTING → NORMALIZING → RULE_EVALUATION → 可选 AI_ENRICHING → COMPLETED。任何执行阶段可因未完成必需工作终结为 PARTIAL、不可恢复执行故障为 FAILED、取消为 CANCELLED。AI 故障只写 ai_status=failed，不把已完成确定性链路改为 FAILED。

取消适用于排队和全部活动阶段：停止派发、取消当前模块 context、等待有界清理、固化已采证据与未覆盖项。超时与取消分开 reason_code；不会删除既有证据。终态后不继续写入同 attempt，重试新建 attempt。任务状态是执行完成度，不代表规则全 PASS。

ModuleStatus：success/partial/failed/not_available/not_applicable/timeout/cancelled/skipped。Evidence.collection_status沿用现有scan-result-v1 Schema的success/partial/failed/not_available/not_applicable/timeout/cancelled；未运行skipped记录在模块覆盖而非伪造Evidence。Completeness：complete/partial/unavailable。IntegrityStatus：verified/unverified/failed/unavailable。RuleOutcome：PASS/FAIL/UNKNOWN/NOT_APPLICABLE。明确适用性不满足才用 NOT_APPLICABLE；工具缺失、权限不足、解析错误、无基线必须 UNKNOWN。

## 4. 关系和覆盖率

数据库/应用层同时验证 Evidence、RuleResult、Finding、Assessment 的 host_id/scan_id 关系，禁止仅检查 ID 字符串存在。跨次扫描变化检测单独引用已授权可信 baseline_scan_id，不把基线证据冒充本次采集。Finding 引用失败 Evidence 只能描述“采集失败”事实，不能据此推断检测属性。

模块覆盖率 = 完成且满足必需字段的适用模块 / 本 Profile 计划适用模块；不适用项单列，失败/权限不足/截断仍在分母。规则覆盖率同理，UNKNOWN 单列。报告同时展示计划数、成功、部分、失败、跳过、不适用，禁止只报告比例而隐藏分母。

## 5. 关联与契约测试

资产和计划采用独立 JSON Schema；未来 Evidence、Finding、ScanResult、Assessment 和 Bundle 也各自版本化。Schema 验证类型/必填/枚举/长度，Go 领域层验证授权、同主机扫描、唯一性、审批、时间先后与摘要。测试覆盖零证据 Finding、跨 host/scan 引用、失败证据当成功、重复 ID、无基线变化、时间倒置、取消后写入以及 AI 严重度覆盖。任何关系校验失败都不能写成有效报告结论。
