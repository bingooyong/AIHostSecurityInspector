# HOSTSEC-40 — 统一只读工具执行器

## 目标与范围
固定二进制/参数白名单、版本、退出码、超时、输出字节上限

## 前置任务
HOSTSEC-04。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
固定二进制/参数白名单、版本、退出码、超时、输出字节上限。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
第三方工具固有写入

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/COLLECTOR-SDD.md
- docs/implementation/TOOL-EVALUATION.md
- docs/04-security/SECURITY-BOUNDARIES.md
