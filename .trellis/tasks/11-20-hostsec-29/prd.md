# HOSTSEC-29 — Codex Claude Skill接入

## 目标与范围
只调用已实现CLI，授权/计划/报告流程；无任意shell能力

## 前置任务
HOSTSEC-28, HOSTSEC-19, HOSTSEC-36。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
只调用已实现CLI，授权/计划/报告流程；无任意shell能力。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
Skill模板误报能力已交付

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/MCP-SDD.md
- docs/03-sdd/CLI-SDD.md

产品Skill分发源位于integrations/skills/，安装适配可写对应客户端约定目录；开发工作流既有.agents/.claude文件不得覆盖。
