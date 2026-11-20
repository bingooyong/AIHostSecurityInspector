# HOSTSEC-32A — 本地有效审批与可追加审计

日期2026-11-20；交付状态 **PLANNED**。本次只细化规划，未声称新增业务实现或测试结果。目录契约统一为backend单Go module；所有路径均为仓库根相对路径。

## 目标与当前事实

- R32A-1：deep/IR执行必须有真实签名、可信签名者/权限、明确操作人与审批人分离、有效期/窗口/撤销状态和范围绑定；approval-id只作查找，不能作授权本身。
- R32A-2：签名覆盖04冻结的ExecutionIntent摘要与主体/nonce/有效期等安全字段；不依赖07规划器已经实现。
- R32A-3：拒绝未知签名者、伪造、过期/未来、撤销、同人、跨目标/Profile/区域、计划变化和重放；所有拒绝安全留痕。
- R32A-4：一次性消费审批与审计在并发/崩溃后不重复放行；失败不覆盖证据、不改主机。
- R32A-5：本地受控清单/签名文件不等于平台RBAC；本地真实身份来源、审批密钥托管与权限边界必须先作为部署进入gate确认。

## 前置与输入

DAG前置：HOSTSEC-04, HOSTSEC-06。父子树不代表依赖；实现前读取其真实完成证据。部分任务已有03A贡献，不因此视为全项验收通过。

- `docs/03-sdd/DOMAIN-MODEL.md`
- `docs/03-sdd/CLI-SDD.md`
- `docs/03-sdd/STORAGE-SDD.md`
- `docs/02-architecture/SECURITY-ARCHITECTURE.md`
- `docs/04-security/SECURITY-BOUNDARIES.md`
- `docs/02-architecture/REPOSITORY-LAYOUT.md`

## 交付范围与所有权

实施时由单一任务负责人协调以下文件；共享文件（Schema、CLI、脚本、Makefile）与并行任务串行集成，不能互相覆盖：

- `backend/internal/approval/`
- `backend/internal/audit/`
- `schemas/approval-v1.schema.json`
- `backend/internal/approval/testdata/`
- `backend/internal/audit/testdata/`

未来/尚不存在的交付文件在本PRD中是计划，不作为当前代码存在的证据。Go源码不回到仓库根；前端/常驻Agent/平台服务不以空工程形式凑交付。

## 验收矩阵

| 判据 | 计划新增测试 | 期望 |
|---|---|---|
| 签名 | 无害测试密钥合法、错签/缺签/改字段/未知key/算法 | 仅允许明确受支持算法和可信key映射，其他拒绝 |
| 主体分离 | trusted principal+key identity映射 | requester/approver字符串不同但来自同一未验证声明仍拒绝 |
| 计划绑定 | 04intent vector与资产/策略/身份/路径/预算变动 | 任一绑定差异拒绝，不让ID相同掩盖内容变化 |
| 时效/窗口 | 注入clock的边界、未来、到期、撤销、时区窗口 | 过期即拒绝，未知时区/回退时钟需安全策略 |
| 防重放 | 两线程/两进程同时consume同nonce、崩溃恢复 | 至多一次允许；audit写失败不允执行 |
| 受控存储 | symlink/非普通文件/目录权限/截断帧/磁盘满 | 失败关闭，无静默重建“空replay库” |
| 无执行能力 | 单元/集成fixture，无host命令 | 验证器只返回决策，不启动/修复主机 |

## 不在本任务

生产或未授权主机连接、自动处置、任意Shell/SQL、安装扫描器或常驻Agent、外发敏感原文、未经授权远端发布均不在范围。未来依赖尚未实现的运行链路必须单独集成验收，不能用fixture或交叉编译替代。

## 风险与未决进入条件

本地owner可改信任根/私钥/journal时无法证明独立审批；不能只比较两个ID字符串。fsync前返回allow、只用mutex防并发或重建损坏replay状态会造成重复放行。

未知若只影响未来真实部署则保留对应gate；若影响签名/身份/兼容等当前契约，先收敛设计再实现，不能由Agent猜测环境。
