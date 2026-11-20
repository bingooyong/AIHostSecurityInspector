# 多工程目录、规范与AGENTS更新报告

2026-11-20。用户要求Go不在仓库根、明确后续CLI/Agent/前端工程边界，并系统更新AGENTS.md。本轮目录迁移和治理文档交付IMPLEMENTED；MVP整体仍PARTIAL，不把本轮规划/结构调整当新增扫描能力。

## 交付与职责

| 项目 | 状态 | 结果 |
|---|---|---|
| Go工程迁移 | IMPLEMENTED | backend/go.mod、go.sum、.golangci.yml；10个Go源码均在backend，imports采用module/backend |
| 程序/工程边界 | IMPLEMENTED（设计） | backend/cmd多binary、internal共用内核；未来frontend独立TS、integrations产品接入；Agent与AI Agent分清 |
| 根构建与CI | IMPLEMENTED（本地验证/配置） | 根Makefile调度backend；CI读取backend/go.mod/go.sum；产物仍根build，远端CI未运行 |
| 工程规范 | IMPLEMENTED | [目录规范](../../.trellis/spec/backend/go/directory-structure.md)使用七节可执行契约，含命令/错误/案例/测试；Trellis登记backend包/go层 |
| AGENTS.md | IMPLEMENTED | 项目定位、目录硬约束、Go依赖边界、安全、证据/AI、开发命令、Trellis/并行/状态/证据/共享工作区；原托管块逐字保留 |
| WP1滚动细化 | IMPLEMENTED（规划） | 7个活动任务的21份prd/design/implement与[详细计划](WP1-DETAILED-PLAN.md)，共62项有序内部检查项；无新增Trellis记录 |
| DAG/上下文 | IMPLEMENTED | 48节点当前交付路径、包、模块SDD/jsonl引用同步；项目仍1主控+48子任务 |
| 来源/旧证据 | IMPLEMENTED（完整性复核） | 22个V1源文件和33个bootstrap历史证据摘要不变；新证据独立存layout-migration |

工程决定见[REPOSITORY-LAYOUT](../02-architecture/REPOSITORY-LAYOUT.md)、[ADR-008](../07-decisions/ADR/ADR-008.md)；官方依据见[GO-LAYOUT-REFERENCES](GO-LAYOUT-REFERENCES.md)。backend/frontend是用户多工程约束下的项目选择，采用Go官方cmd/internal惯例；没有把它误称Go唯一合法布局，也没有为空壳引入多个module/go.work。

## 行为锁定与实际验证

迁移前：已有race测试通过；冻结11条真实CLI stdout/stderr/exit及源码摘要。迁移只改变目录、module/import路径、测试fixture相对路径和构建调度，不修改CLI业务字段/规则/授权，不加依赖。

迁移后[正式结果](../05-testing/evidence/layout-migration/results.json)的16门禁全部PASS：目录结构、格式、go mod verify、vet、race、lint、AST边界、本机构建、11行为比对、27真实CLI/Schema、未来Schema形状、DAG/来源/文档/AGENTS/Trellis、漏洞、SBOM、双Linux架构构建、空白检查。各结果记录真实cwd/命令/退出码/日志；源码摘要与产物清单在同目录。

本机11条行为逐字相同。CI跨OS/架构/Go版本时，仅允许doctor.os/architecture/linux_platform_supported与version.go_version按真实环境适配，其他stdout/stderr/exit必须一致且日志说明portable模式。独立审查用有界模拟验证该分支，并确认execution_ready篡改仍失败。

[独立审查](../security/LAYOUT-INDEPENDENT-REVIEW.md)复跑race/vet/lint/CLI/Schema/AST/路径与托管块、历史证据检查，没有切片内未修复发现。单module/internal不是权限边界，特权Collector未来必须验证窄传递依赖树；当前不创建空Collector/Agent/前端工程。

漏洞扫描仍是零可达/导入包漏洞，Go1.27.3标准库有未被当前CLI使用的GO-2026-6859（1.27.4修复），原风险R14保留。交叉编译仅证明构建；Linux Collector、SSH、AI、运行资源守卫和真实远端CI验收尚未执行。

## 规范与任务收敛

- 新AGENTS.md是项目级入口，详细合同放spec/SDD/ADR，避免复制整套通用平台说明。原文件只有Trellis托管块，未伪造OMX生成块；用户提供的自治约定已写在托管块外。
- 目录门禁阻止根Go工程回归；基线门禁检查AGENTS规范入口/标记、真实package/layer、文档链接与全部任务上下文，不只依赖聊天记忆。
- WP1审查发现的旧Completeness none/Schema unavailable等文档漂移已修正；04仍须实现字段一致性、ExecutionIntent规范化/hash和测试，再由32A验证、07集成，避免审批计划依赖成环。
- 32A真实身份/密钥托管/目录所有权与持久审计属于启用gate，用户名字符串不同不足以证明操作审批分离。05真实status/retry/resume依赖后续存储/执行用例，不用成功占位。

HOSTSEC-03与42的目录/门禁切片已实现，完整任务仍PARTIAL；其余业务状态未因规划细化改变。没有发布、部署、Git提交或生产访问。下一切片按WP1计划推进04领域/Schema/执行意图，保留当前工作区与真实完成证据。
