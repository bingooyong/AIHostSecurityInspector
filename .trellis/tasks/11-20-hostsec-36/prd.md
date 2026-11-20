# HOSTSEC-36 — 调度状态机与端到端扫描

## 目标与范围
模块隔离超时/取消/压力停止/限额，计划授权复核，失败不变PASS

## 前置任务
HOSTSEC-07, HOSTSEC-08, HOSTSEC-09, HOSTSEC-10, HOSTSEC-11, HOSTSEC-12, HOSTSEC-13, HOSTSEC-14, HOSTSEC-16, HOSTSEC-17, HOSTSEC-32A, HOSTSEC-37, HOSTSEC-38。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
模块隔离超时/取消/压力停止/限额，计划授权复核，失败不变PASS。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
资源耗尽与丢证据

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/COLLECTOR-SDD.md
- docs/03-sdd/STORAGE-SDD.md
- docs/03-sdd/EVIDENCE-SDD.md
