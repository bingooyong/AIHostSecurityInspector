# HOSTSEC-25 — AI Provider抽象

## 目标与范围
默认禁用，OpenAI/兼容/本地统一请求限制

## 前置任务
HOSTSEC-18, HOSTSEC-19。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
默认禁用，OpenAI/兼容/本地统一请求限制。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
Provider重定向/SSRF/secret日志

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/AI-ANALYZER-SDD.md
- docs/03-sdd/EVIDENCE-SDD.md
- docs/04-security/DATA-GOVERNANCE.md
