# HOSTSEC-17 — 有限DSL YAML规则引擎

## 目标与范围
9条MVP规则含required_evidence与PASS/FAIL/UNKNOWN/N/A；不执行代码

## 前置任务
HOSTSEC-18, HOSTSEC-44。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
9条MVP规则含required_evidence与PASS/FAIL/UNKNOWN/N/A；不执行代码。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
规则包供应链和假绿

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/RULE-ENGINE-SDD.md
- docs/03-sdd/DOMAIN-MODEL.md
