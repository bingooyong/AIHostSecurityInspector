# HOSTSEC-31 — 区域Runner

## 目标与范围
区域隔离、签名任务、mTLS、nonce/有效期/反重放

## 前置任务
HOSTSEC-30, HOSTSEC-41, HOSTSEC-32。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
区域隔离、签名任务、mTLS、nonce/有效期/反重放。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
中央跨区访问和凭据复用

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/MCP-SDD.md
- docs/03-sdd/EVIDENCE-SDD.md
- docs/06-operations/DEPLOYMENT.md
