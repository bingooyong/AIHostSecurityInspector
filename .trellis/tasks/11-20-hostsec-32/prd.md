# HOSTSEC-32 — 平台审批与审计

## 目标与范围
操作审批分离、审批绑定、审计只读、持久化留痕

## 前置任务
HOSTSEC-32A, HOSTSEC-19。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
操作审批分离、审批绑定、审计只读、持久化留痕。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
管理员绕过审批

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/MCP-SDD.md
- docs/03-sdd/DOMAIN-MODEL.md
- docs/02-architecture/SECURITY-ARCHITECTURE.md
