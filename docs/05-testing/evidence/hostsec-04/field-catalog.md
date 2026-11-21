# HOSTSEC-04 字段/枚举对照

日期：2026-11-20。实现包：`backend/internal/domain`。Schema：`schemas/scan-result-v1.schema.json`、`schemas/execution-intent-v1.schema.json`。

| 概念 | 允许值 | 代码位置 |
|---|---|---|
| collection_status | success/partial/failed/not_available/not_applicable/timeout/cancelled | `enums.go`；skipped 只用于模块覆盖 |
| completeness | complete/partial/unavailable | 无历史 none |
| integrity_status | verified/unverified/failed/unavailable | verified 必须带双 SHA-256 |
| RuleOutcome | PASS/FAIL/UNKNOWN/NOT_APPLICABLE | PASS/FAIL 禁止缺证据 |
| ScanJob | CREATED…COMPLETED/PARTIAL/FAILED/CANCELLED/REJECTED | 终态不可原地重写 |
| ExecutionIntent canonical | execution-intent-canonical-v1 | 不含 plan_id/展示文字/approval/execution_ready |
| mode | READ_ONLY | 其它值拒绝 |

Go 关系校验覆盖：跨 host/scan、重复 ID、失败证据支撑 PASS、无基线 NO_CHANGE、AI 引用集合外证据、时间倒置。
