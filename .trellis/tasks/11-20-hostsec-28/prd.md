# HOSTSEC-28 — AI证据引用验证

## 目标与范围
每结论绑定同scan-host真实允许证据集合

## 前置任务
HOSTSEC-27, HOSTSEC-16。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
每结论绑定同scan-host真实允许证据集合。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
存在ID但不支持结论

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/AI-ANALYZER-SDD.md
- docs/03-sdd/EVIDENCE-SDD.md
- docs/04-security/DATA-GOVERNANCE.md
