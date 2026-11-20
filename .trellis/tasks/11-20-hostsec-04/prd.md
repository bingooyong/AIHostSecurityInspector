# HOSTSEC-04 — 领域模型与版本化Schema

日期2026-11-20；交付状态 **PARTIAL**。本次只细化规划，未声称新增业务实现或测试结果。目录契约统一为backend单Go module；所有路径均为仓库根相对路径。

## 目标与当前事实

- R04-1：Host、Plan、ScanJob、Attempt、Evidence、RuleResult、Finding、Assessment、Approval/Audit契约有一致枚举/ID/时间/版本/JSON字段，并保持当前资产/离线plan兼容。
- R04-2：执行状态、采集状态、规则四态、人工复核状态分开；缺证据/权限/基线不能转换成PASS或无证据Finding。
- R04-3：引用校验包含同host/scan归属、ID唯一、完整性/采集状态和结论用途，Schema形状验证不能代替关系验证。
- R04-4：为32A先冻结可签名执行意图和规范化摘要输入，不要求07规划器已实现；避免审批与计划互相依赖。
- R04-5：不提前建数据库/扫描器/模型接口空实现；每个新增实体必须有实际序列化、校验与关系测试。

## 前置与输入

DAG前置：HOSTSEC-03A。父子树不代表依赖；实现前读取其真实完成证据。部分任务已有03A贡献，不因此视为全项验收通过。

- `docs/03-sdd/DOMAIN-MODEL.md`
- `docs/03-sdd/CLI-SDD.md`
- `docs/03-sdd/EVIDENCE-SDD.md`
- `docs/03-sdd/AI-ANALYZER-SDD.md`
- `docs/02-architecture/REPOSITORY-LAYOUT.md`
- `schemas/scan-result-v1.schema.json`

## 交付范围与所有权

实施时由单一任务负责人协调以下文件；共享文件（Schema、CLI、脚本、Makefile）与并行任务串行集成，不能互相覆盖：

- `backend/internal/domain/`
- `backend/internal/asset/asset.go`
- `backend/internal/planner/planner.go`
- `schemas/scan-result-v1.schema.json`
- `schemas/assets-v1.schema.json`
- `schemas/plan-v1.schema.json`
- `backend/internal/domain/testdata/`

未来/尚不存在的交付文件在本PRD中是计划，不作为当前代码存在的证据。Go源码不回到仓库根；前端/常驻Agent/平台服务不以空工程形式凑交付。

## 验收矩阵

| 判据 | 计划新增验证 | 负例 |
|---|---|---|
| Go模型和Schema一致 | 每实体合法往返+Schema，同一fixture双验证 | 未知字段、错误枚举、空ID、null类型、越界confidence |
| 状态语义独立 | 合法转换表与终态不可写测试 | FAILED/UNKNOWN被当PASS、取消后继续同attempt |
| Evidence/Finding关联 | 一个实际内存快照包含host/scan/attempt对象及引用验证 | 伪ID、重复ID、跨host/scan、无证据Finding、失败采集证明安全 |
| 历史变化可信 | 显式baseline_ref和来源状态 | 首次/不可信/覆盖不足基线仍判“无变化” |
| 规范化摘要稳定 | 顺序/空值/版本/整数类型规范及golden摘要 | 相同意图map顺序不同hash、不同范围同hash |
| 兼容现有CLI | 03A基线命令与Schema仍通过 | 类型移动改变JSON tag、默认空数组变null |

## 不在本任务

生产或未授权主机连接、自动处置、任意Shell/SQL、安装扫描器或常驻Agent、外发敏感原文、未经授权远端发布均不在范围。未来依赖尚未实现的运行链路必须单独集成验收，不能用fixture或交叉编译替代。

## 风险与未决进入条件

现有SDD与Schema有枚举漂移，必须先收敛；同ID存在不证明证据支持结论；canonicalization若未版本化会使审批校验不稳定；当前并无真实采集可验。

未知若只影响未来真实部署则保留对应gate；若影响签名/身份/兼容等当前契约，先收敛设计再实现，不能由Agent猜测环境。
