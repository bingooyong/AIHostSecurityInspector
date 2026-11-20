# HOSTSEC-06 — 资产清单、授权与差异治理

日期2026-11-20；交付状态 **PARTIAL**。本次只细化规划，未声称新增业务实现或测试结果。目录契约统一为backend单Go module；所有路径均为仓库根相对路径。

## 目标与当前事实

- R06-1：保留严格YAML/JSON输入、稳定非IP主机ID、显式authorized与allowed_profiles、组/标签和业务归属，认证仅引用。
- R06-2：对一个校验后的完整资产快照生成可重现版本摘要，计划记录快照；执行前重读并复核，不把一次校验当永久授权。
- R06-3：提供按host_id的added/removed/changed差异，不把IP变化认作新稳定身份，也不将不完整清单解读为自动撤权或整改成功。
- R06-4：所有目标选择仍全组原子授权；不接受裸IP/网段或自动扩大目标。资产文件由受控本地管理员维护，不声称它实现平台RBAC。
- R06-5：主机真实身份漂移需要14/08输出，当前实现引用/比较契约并以无害fixture测试，不通过联网“确认”资产。

## 前置与输入

DAG前置：HOSTSEC-05。父子树不代表依赖；实现前读取其真实完成证据。部分任务已有03A贡献，不因此视为全项验收通过。

- `docs/03-sdd/CLI-SDD.md`
- `docs/03-sdd/DOMAIN-MODEL.md`
- `docs/04-security/SECURITY-BOUNDARIES.md`
- `docs/02-architecture/REPOSITORY-LAYOUT.md`
- `schemas/assets-v1.schema.json`

## 交付范围与所有权

实施时由单一任务负责人协调以下文件；共享文件（Schema、CLI、脚本、Makefile）与并行任务串行集成，不能互相覆盖：

- `backend/internal/asset/`
- `backend/internal/authorization/`
- `schemas/assets-v1.schema.json`
- `examples/hosts.yaml`
- `backend/internal/asset/testdata/`

未来/尚不存在的交付文件在本PRD中是计划，不作为当前代码存在的证据。Go源码不回到仓库根；前端/常驻Agent/平台服务不以空工程形式凑交付。

## 验收矩阵

| 判据 | 计划测试 | 期望 |
|---|---|---|
| 严格输入兼容 | JSON/YAML同内容、null/duplicate/unknown/alias/merge/depth/size/FIFO回归 | 当前负例继续拒绝，空清单可解析但不能计划 |
| 稳定身份 | IP形ID、重复host_id、多地址/组悬空/重复成员 | 整份清单拒绝，无部分成功 |
| 原子授权 | 混合组、Profile撤销、缺授权、未登记ID | 任一不满足则无计划和无目标访问 |
| Snapshot摘要 | 键顺序/文档格式差异、Profile/地址/权限实质变动 | 同语义摘要稳定；安全相关变化改变摘要 |
| 差异 | 同ID地址/owner/Profile变化、主机新增/删除、字段删改 | 明确字段名/前后摘要，秘密字段不输出 |
| 执行复核 | 计划后authorized/Profile/zone/known_hosts_ref变化、文件替换 | 拒绝旧快照，不能静默套用新地址或权限 |
| 身份漂移 | 指纹不一致/未知/未采集fixture | 未知不当相同；真实核验留08/14门禁 |

## 不在本任务

生产或未授权主机连接、自动处置、任意Shell/SQL、安装扫描器或常驻Agent、外发敏感原文、未经授权远端发布均不在范围。未来依赖尚未实现的运行链路必须单独集成验收，不能用fixture或交叉编译替代。

## 风险与未决进入条件

JSON hash不是资产真实性/授权来源保证；可写清单与identity声明不能抵御本机管理员；计划后配置变更和map/slice别名可绕过错误实现。

未知若只影响未来真实部署则保留对应gate；若影响签名/身份/兼容等当前契约，先收敛设计再实现，不能由Agent猜测环境。
