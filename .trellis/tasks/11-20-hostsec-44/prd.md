# HOSTSEC-44 — 可信基线与扫描差异

## 目标与范围
审批基线、host identity、SSH key/config/服务差异、历史attempt

## 前置任务
HOSTSEC-16, HOSTSEC-06。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
审批基线、host identity、SSH key/config/服务差异、历史attempt。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
攻击后快照被当可信基线

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/EVIDENCE-SDD.md
- docs/03-sdd/RULE-ENGINE-SDD.md
- docs/03-sdd/STORAGE-SDD.md
