# HOSTSEC-15 — 本地SQLite和证据落盘

## 目标与范围
事务迁移、只追加raw/normalized、安全权限与崩溃恢复

## 前置任务
HOSTSEC-04。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
事务迁移、只追加raw/normalized、安全权限与崩溃恢复。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
证据文件与元数据非原子

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/STORAGE-SDD.md
- docs/03-sdd/EVIDENCE-SDD.md
