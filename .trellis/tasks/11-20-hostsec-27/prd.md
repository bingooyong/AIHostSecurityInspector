# HOSTSEC-27 — 结构化AI关联研判

## 目标与范围
规定11字段、事实推断分离、severity不变、失败降级

## 前置任务
HOSTSEC-26, HOSTSEC-19。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
规定11字段、事实推断分离、severity不变、失败降级。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
AI越权结论或指令

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/AI-ANALYZER-SDD.md
- docs/03-sdd/EVIDENCE-SDD.md
- docs/04-security/DATA-GOVERNANCE.md
