# HOSTSEC-39 — 离线漏洞情报关联

## 目标与范围
可信版本化情报与发行版回补语义，缺情报UNKNOWN

## 前置任务
HOSTSEC-38, HOSTSEC-17。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
可信版本化情报与发行版回补语义，缺情报UNKNOWN。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
字符串版本比较误报

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/RULE-ENGINE-SDD.md
- docs/03-sdd/COLLECTOR-SDD.md
- docs/implementation/TOOL-EVALUATION.md
