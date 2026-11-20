# HOSTSEC-11 — Linux账号权限采集

## 目标与范围
用户组/UID0/sudo/公钥指纹/登录；不读私钥

## 前置任务
HOSTSEC-08。父子结构不代表依赖；以 task-dag.json 为准。

## 输入
- docs/01-product/PRD.md
- docs/04-security/SECURITY-BOUNDARIES.md
- docs/05-testing/ACCEPTANCE-CRITERIA.md

## 验收
用户组/UID0/sudo/公钥指纹/登录；不读私钥。所有交付有真实完成证据，PLANNED 不等于 IMPLEMENTED。

## 风险
用户隐私与密钥外泄

状态 PLANNED；实施前细化本任务技术未知，不扩大授权范围。

## 模块接口输入
- docs/03-sdd/COLLECTOR-SDD.md
- docs/03-sdd/DOMAIN-MODEL.md
