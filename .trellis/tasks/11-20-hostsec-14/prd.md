# HOSTSEC-14 — SSH固定Collector Transport

## 目标与范围
严格known_hosts、专用账号、固定部署二进制与参数，禁止任意exec

## 前置任务
HOSTSEC-08, HOSTSEC-32A。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
严格known_hosts、专用账号、固定部署二进制与参数，禁止任意exec。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
SSH远端本质命令字符串需封闭常量构造

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/02-architecture/SECURITY-ARCHITECTURE.md
- docs/03-sdd/COLLECTOR-SDD.md
