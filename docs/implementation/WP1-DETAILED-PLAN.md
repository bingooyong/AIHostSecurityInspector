# WP1 近期任务详细实施计划

日期2026-11-20。本次把7个活动任务的PRD/design/implement从通用概要细化为字段/接口/状态/错误/测试/回滚/证据计划。**这是规划交付，不改变任务业务实现状态。** 不创建新的Trellis记录；现有WP1仍为8个节点（含归档HOSTSEC-03A），HostSec整体仍是1主控+48子任务。

## 当前事实与目录

03A已实现离线资产→授权→四Profile计划，未实现Collector、扫描、审批、证据存储、规则、AI或前端。当前用户明确Go不能位于仓库根：backend是唯一Go module，cmd分程序、internal共享核心，frontend为后续TS工程，integrations为产品Skill/MCP调用材料，schemas/示例/文档/调度为仓库级内容。常驻主机Agent和AI Agent不同，MVP仍只计划一次性固定Collector。

权威目录为`docs/02-architecture/REPOSITORY-LAYOUT.md`和ADR-008。所有新任务交付路径均以backend开头；归档03A及bootstrap证据保留其历史时点，不篡改原日志路径来冒充迁移后验证。

## 节点与内部分解数量

| WP1节点 | 当前交付 | 内部有序检查项 | DAG前置 |
|---|---|---:|---|
| HOSTSEC-03A | IMPLEMENTED（归档首切片） | 7（原归档计划，未改写） | HOSTSEC-00/01/02 |
| HOSTSEC-03 | PARTIAL | 8 | HOSTSEC-03A |
| HOSTSEC-04 | PARTIAL | 9 | HOSTSEC-03A |
| HOSTSEC-05 | PARTIAL | 8 | HOSTSEC-03, HOSTSEC-04 |
| HOSTSEC-06 | PARTIAL | 8 | HOSTSEC-05 |
| HOSTSEC-32A | PLANNED | 10 | HOSTSEC-04, HOSTSEC-06 |
| HOSTSEC-07 | PARTIAL | 10 | HOSTSEC-06, HOSTSEC-32A |
| HOSTSEC-42 | PARTIAL | 9 | HOSTSEC-03A |

7个活动节点共 **62项内部实施检查项**，用于执行顺序和验收，不是额外62个子任务，也不表示62个独立可并行单元。原归档03A七项保持历史原文。当前6个PARTIAL、1个PLANNED的交付状态未因文档完善变为IMPLEMENTED。

## 建议实施波次

1. **当前切片：03目录迁移 + 42门禁路径适配。** 先跑迁移前race、冻结11条真实CLI输出，再移动backend工程并对比，修root调度/CI/cache/hash/SBOM。迁移完成仅关闭这个切片，不把03完整版本/可复现发布或42远端CI一并关闭。
2. **下一切片：04领域/版本/ExecutionIntent摘要。** 收敛现有SDD与Schema枚举差异，冻结签名意图hash与JSON/错误/时间/关系验证；03剩余构建发布可在文件互斥时并行。04不等候所有Collector实现。
3. **05 CLI合同 → 06资产快照/差异/执行复核。** 现有CLI参数和输出为兼容基线；未来状态/报告接入需等待真实用例，不创建成功占位。06保持本地受控清单信任边界，不冒充平台RBAC。
4. **32A签名审批与审计 → 07可执行计划/策略Preflight。** 32A接04纯ExecutionIntent与06快照，不依赖07规划器。07构建同一意图并集成32A，按DAG先审批验证再完成执行前复核。
5. **WP2/3实际运行链路汇合。** 08系统与15证据可按依赖推进；14/36结合真实身份、有效审批、资源守卫和状态机，在隔离Linux测试后才允许scan。WP1的纯验证通过不能替代这一运行gate。

42贯穿每个波次：当前现有Go/CLI门禁真跑，未来规则/Collector/AI/前端实现后启用相应必跑job；当前无前端不创建空package.json或假成功job。

## 关键合同与真实未知

| 项目 | 本次细化决定 / 进入条件 | 归属 |
|---|---|---|
| Schema枚举漂移 | 本轮已把SDD的none收敛为Schema unavailable并补齐timeout/integrity unavailable；04仍须逐字段实现一致枚举和模块skipped到证据的显式映射测试，不能静默兼容成安全通过 | 04 |
| 审批与计划依赖 | 04冻结规范化ExecutionIntent/hash，32A验证typed输入，07集成；DAG不加32A→07反向依赖 | 04/32A/07 |
| 本地审批真实身份 | trust store将key绑定principal和权限；操作身份不得由CLI/JSON自报。企业OS身份/密钥托管/目录权限尚未提供，真实运行启用前需确认；字符串不同不等于独立审批 | 32A/14/36 |
| 32A早于SQLite | 最小可恢复append-only journal+跨进程锁+消费与允许审计同一持久事件；不隐式将15数据库变成循环前置；选型与崩溃测试必须先过 | 32A/15 |
| 计划ready与守卫 | 离线描述和Preflight不等于执行；当前execution_ready=false、limits.enforced=false保持，36/37/40后验真实限额 | 07/36/37/40 |
| CLI全生命周期 | 05可验证解析/编码/context，真实status/retry/resume需15/36；各自单元合同与跨任务运行验收分开报告 | 05/15/36 |
| 特权Collector依赖 | 同Go module不是权限隔离，Collector单binary不得导入Analyzer/Provider/API/DB/任意Shell，进入08/14时固化依赖树门禁 | 03/08/14 |
| 本地与远端验证 | 本地命令PASS/交叉构建/Schema形状不等于GitHub run/Linux采集/引用真实性；远端运行需真实触发证据，不为取证擅自推送 | 42/43 |

当前不存在阻止**目录迁移与纯领域/Schema切片**的产品决策阻塞。32A的真实企业身份与密钥托管、Linux运行环境/权限/窗口是后续启用gate；可以先用隔离无害fixture实现并验证拒绝逻辑，但不能据此宣称企业审批隔离已验收。

## 统一完成协议

每个任务实施前读其prd/design/implement与jsonl上下文，核对前置实际完成证据和共享文件所有权。字段/错误/状态有正反例，安全关键路径有权限/恶意/取消/资源负例；运行功能有真实过程与产物。日志保存命令、cwd、退出码、源码/工具链、产物hash和限制，原日志不覆盖。只有本任务全部验收满足才更新IMPLEMENTED；PARTIAL写缺项，真实环境阻塞写BLOCKED，未来功能PLANNED。
