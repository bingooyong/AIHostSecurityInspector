# HOSTSEC-33 — Go Web API

## 目标与范围
共用应用服务、授权和审计，不复制检测内核

## 前置任务
HOSTSEC-30, HOSTSEC-31, HOSTSEC-32, HOSTSEC-45。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
共用应用服务、授权和审计，不复制检测内核。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
多入口授权差异

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/02-architecture/SYSTEM-ARCHITECTURE.md
- docs/03-sdd/MCP-SDD.md
