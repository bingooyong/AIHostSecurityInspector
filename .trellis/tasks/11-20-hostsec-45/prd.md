# HOSTSEC-45 — 身份与区域RBAC

## 目标与范围
按用户/组/区域/业务授权，审计只读、Agent继承调用者

## 前置任务
HOSTSEC-32。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
按用户/组/区域/业务授权，审计只读、Agent继承调用者。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
平台管理员隐式全权限

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/MCP-SDD.md
- docs/02-architecture/SECURITY-ARCHITECTURE.md
