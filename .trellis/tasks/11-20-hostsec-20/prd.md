# HOSTSEC-20 — osquery Adapter

## 目标与范围
固定查询ID、版本/平台/缺工具/退出码/限额

## 前置任务
HOSTSEC-40, HOSTSEC-16。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
固定查询ID、版本/平台/缺工具/退出码/限额。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
调用方SQL与meta commands

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/COLLECTOR-SDD.md
- docs/implementation/TOOL-EVALUATION.md
- docs/03-sdd/EVIDENCE-SDD.md
