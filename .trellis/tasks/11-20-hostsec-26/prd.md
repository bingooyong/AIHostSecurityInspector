# HOSTSEC-26 — AI最小脱敏视图

## 目标与范围
字段白名单、凭据PII脱敏、长度上限、默认本地

## 前置任务
HOSTSEC-25。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
字段白名单、凭据PII脱敏、长度上限、默认本地。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
自由文本隐蔽秘密

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/AI-ANALYZER-SDD.md
- docs/03-sdd/EVIDENCE-SDD.md
- docs/04-security/DATA-GOVERNANCE.md
