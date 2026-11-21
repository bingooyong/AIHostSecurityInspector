<!-- AUTONOMY DIRECTIVE — DO NOT REMOVE -->
YOU ARE AN AUTONOMOUS CODING AGENT. EXECUTE TASKS TO COMPLETION WITHOUT ASKING FOR PERMISSION.
DO NOT STOP TO ASK "SHOULD I PROCEED?" — PROCEED. DO NOT WAIT FOR CONFIRMATION ON OBVIOUS NEXT STEPS.
IF BLOCKED, TRY AN ALTERNATIVE APPROACH. ONLY ASK WHEN TRULY AMBIGUOUS OR DESTRUCTIVE.
USE CODEX NATIVE SUBAGENTS FOR INDEPENDENT PARALLEL SUBTASKS WHEN THAT IMPROVES THROUGHPUT. THIS IS COMPLEMENTARY TO OMX TEAM MODE.
<!-- END AUTONOMY DIRECTIVE -->

# HostSec 工程协作约定

本文件约束整个仓库。项目是企业主机只读安全巡检平台：确定性工具发现、规则判断、AI辅助研判、证据支撑、人工决策。所有入口复用同一执行内核，不把安全检测写成Agent提示词或临时Shell脚本。

## 0. 开发命令与当前能力

以下命令从仓库根运行，定义以 `Makefile`、`scripts/`、`backend/go.mod` 和 CI 为准，不按模板猜测。当前 Go 版本为 1.27.4（补丁级升级以修复 GO-2026-6859），Python 依赖固定在 `scripts/requirements.txt`；版本变化时同步本节。

| 命令 | 用途与副作用 |
| --- | --- |
| `make build` | 构建本地 `build/hostsec`，不连接主机 |
| `make test` | `backend/` 中执行 race 测试，禁用测试缓存 |
| `make vet` / `make lint` | Go 静态检查；lint 需要已安装验证工具 |
| `make boundaries` | Go AST 执行/导入安全边界检查 |
| `make baseline` | DAG、来源完整性、上下文、文档链接和托管块检查；不证明扫描可用 |
| `make layout` | 构建并验证目录与既有 CLI 行为 |
| `make schema` / `make integration` | 构建并运行当前离线 CLI/Schema 集成检查 |
| `make vuln` / `make sbom` | 漏洞可达性检查与 SBOM；可能访问外部情报/模块源，按任务网络授权执行 |
| `make check` | 聚合质量门禁并写验证日志；运行前检查下述历史证据保护约束 |
| `make release` | 生成 Linux 双架构本地制品与 manifest；不创建 Git Tag/Release、不推送或部署 |

按需安装验证依赖：`python3 -m pip install -r scripts/requirements.txt`、`make tools`。前者写入所选 Python 环境，优先隔离环境；后者将固定版本 Go 工具装入 `build/tools`。安装/下载属于有副作用的依赖操作，不因阅读本文件就自动执行或升级全局工具。

直接检查 Go module 使用：

```sh
go -C backend test -race -count=1 ./...
go -C backend vet ./...
go -C backend mod verify
go -C backend run ./tools/check-boundaries
```

当前 CLI 在离线切片上提供 `version`、`assets validate/list/snapshot/diff`、`plan --dry-run`、`intent`、`preflight`、`inspect-fixture`、`inspect-local`、`inspect-authorized`、`mcp stdio` 和 loopback `api`。`doctor` 明确 Collector 不可用并返回1；plan/preflight/inspect-fixture/inspect-local/inspect-authorized/mcp/api 始终不得把 `collector_available`/`scan_ready`/`execution_ready` 设为 true，`limits.enforced=false`。`hostsec scan` 与 `mcp serve` 仍拒绝。`inspect-authorized` 是操作者显式授权采集路径（清单授权 + 本轮 allowlist + 意图绑定 + SSH strict known_hosts/identity），本发行版只接受 loopback 实验室目标，不是通用内网扫描器。本地 stdio MCP 与 127.0.0.1 API 复用同一授权内核，不是企业扫描或平台身份。不为制造成功而改成0/true，也不把 fixture/本地控制台当成主机扫描。

**历史证据保护：** 当前 `scripts/verify.py` 将聚合结果写入固定的 `docs/05-testing/evidence/layout-migration/`，部分检查还会更新 `build/`。该目录已有需保留的证据时，不直接重跑覆盖旧日志；先为本次验证安排新的证据目录或在隔离副本中运行并记录环境。修改验证脚本的输出机制须有明确任务范围，不能为了本次文档修改顺带改写脚本。新结果不能覆盖原始V1、bootstrap或layout-migration历史证据。

## 1. 先加载实际工程上下文

- 会话开始加载项目 `trellis-start`；续做时读取当前任务及持久化产物，不重建已有任务树。以实际安装的Trellis和工具help为准，不猜命令、模板或运行模式。
- 先读 `docs/02-architecture/REPOSITORY-LAYOUT.md`、`.trellis/spec/backend/go/index.md` 与当前任务 `prd.md`、`design.md`、`implement.md`；实现/检查还必须读取对应jsonl中全部真实规范。
- 需求与范围以用户最新明确指令为准；重大结构/契约修订更新SDD/ADR，不能继续沿用已被替代的旧设计。详细规范只有一份权威来源，本文件给约束与入口，不复制整个SDD。
- 正在执行的主控任务通过 `python3 .trellis/scripts/task.py current --source` 确认；DAG以 `docs/implementation/task-dag.json` 为准。父子树不是依赖图，只有前置验收后才能进入依赖任务。
- 阅读修改路径适用的目录级规则；更具体的规则用于细化模块要求，冲突须指出来源。AGENTS.md提供行为指导，不替代工具权限、CI、分支保护或生产审批。

## 2. 仓库根与Go module根必须分开

| 路径 | 职责与约束 |
|---|---|
| `backend/` | 当前Go module；go.mod/go.sum/.golangci.yml和所有Go源码均在此 |
| `backend/cmd/<binary>/` | 各可执行程序薄入口；当前只有hostsec已实现 |
| `backend/internal/` | 共享领域、应用用例及具体适配；核心逻辑不能堆在cmd/CLI中 |
| `backend/tools/` | Go工程辅助工具；当前AST边界检查器在tools/check-boundaries |
| `frontend/` | 规划的独立React/TypeScript工程；未实施前不创建空npm工程 |
| `integrations/` | 规划的产品Skills、AI Agent/MCP客户端接入材料；不实现检测内核 |
| `schemas/` | 跨语言/跨入口版本化JSON Schema |
| `examples/` | 无害配置示例，使用文档地址和测试数据 |
| `rules/`、`policies/`、`deploy/` | 按后续任务落地的规则/策略/部署资源，不在目录规划阶段伪造实现 |
| `scripts/`、`Makefile`、`.github/` | 仓库级构建/验证/CI调度；scripts下不放Go源码 |
| `docs/`、`.trellis/` | 来源、设计、安全、验收、任务、规范和执行证据 |
| `build/` | 忽略的构建产物与本地验证工具，不能作为源码提交 |

**硬约束：** 根目录不得添加go.mod/go.sum/go.work、根级cmd/internal/pkg、Go源码或Go专用lint配置。唯一当前module为 `github.com/bingooyong/AIHostSecurityInspector/backend`；imports含/backend，保持真实仓库路径大小写。当前单module无需go.work、本地replace或GO111MODULE补丁，不为每个计划中的binary创建独立module。

多binary分别构建/部署：CLI、一次性Linux Collector、区域Runner、MCP、Web API共用领域内核；常驻主机Agent若有真实需求另立安全/生命周期设计。**主机Agent与Codex/Claude等AI Agent不同。** 当前MVP仍采用一次性固定Collector，不默认安装常驻Agent。

`.agents/`、`.claude/`、`.codex/`、`.cursor/`中的现有开发工具文件不等于已交付产品Skills，不随目录迁移覆盖或删除。产品分发材料在integrations，安装时遵循客户端目录规范。

## 3. Go代码与依赖边界

Go任务使用已安装的 `golang-how-to` 路由相关技能；目录变化参考 `golang-project-layout`，以本项目用户约束和实际Go官方规则为准，不机械套用需要额外确认/依赖的模板。

- 遵循Go官方惯例：薄main、职责明确的小写package、测试同目录、窄接口由使用方定义、显式错误与context取消。通过构造函数手动装配；没有实际需求不增加DI框架、无消费者pkg或utils/common层。
- CLI/MCP/API只做请求转换、真实身份恢复和展示，调用共用资产/授权/计划/执行服务；不能绕过授权直接操作主机。
- Collector独立binary只能依赖必要采集/数据契约，不导入Analyzer/模型Provider、数据库或平台服务。`internal`只约束导入可见性，不是权限隔离；Collector任务实现时必须用传递依赖门禁验证，不能只检查直接imports。
- 新依赖须有明确已授权任务需求，固定版本、更新checksum/许可/SBOM并运行相关检查；不因设计图或未来接口先安装数据库、SSH、模型/MCP SDK。没有规模证据不引入Kafka/Kubernetes/复杂微服务。
- 前端通过批准的API/Schema消费结果，不复制Go规则或授权判断；前端落地时有独立锁文件与lint/typecheck/test/build，Trellis再登记真实frontend包。
- 代码风格沿用现有实现：使用gofmt、显式错误传播和context，避免吞错、空实现、硬编码成功及无消费者抽象。不通过删除/弱化断言、跳过失败用例、关闭类型/鉴权/安全检查制造通过。

## 4. 产品执行安全边界

- 默认READ_ONLY。只对明确登记、授权且Profile允许的host_id工作；host_id不是IP地址。组中出现越权目标时整体拒绝，执行前再次核对资产/策略/主机身份和审批，不能按失败目标猜测其他IP。
- 开发与测试不连接生产或未授权地址，不探测网段，不运行真实恶意样本。使用测试VM/容器/无害fixture；样例地址不是真实授权。
- 禁止向CLI/Skill/MCP/API/规则DSL暴露任意Shell、SSH exec、SQL/VQL或外部工具任意参数。开发终端可执行本任务需要的构建/测试命令，这不意味着产品获得通用执行权限。
- SSH严格验证known_hosts/Host Key，固定受控Collector入口及参数；禁止关闭校验、接受任意sudo、root直连、资产文件内联密码/私钥。
- deep与incident-response执行必须验证有效审批，绑定计划摘要、主机/Profile/路径/预算、执行者/审批者、有效期/nonce/窗口；非空approval-id或两个不同的自报用户名不构成有效审批。规划可以无审批，规划不等于执行许可。
- 不自动杀进程、删除/隔离文件、安装卸载、修改账号/配置/服务/网络/防火墙。处置能力若未来提出，单独模块、权限和人工审批，不能复用扫描权限。
- 只读不是零副作用承诺：受控证据/工具日志输出、登录审计与atime需披露；工具必须逐版本审查危险参数和写入范围。文件扫描强制路径白名单/挂载与symlink防逃逸、文件/大小/IO/时间/并发/压力预算，不能只把限额写进plan就称已执行。

## 5. 证据、状态和AI

- Finding必须引用真实、完整性有效、同host_id/scan_id且支撑结论的证据。原始、标准化和AI分析视图分开；ID、采集模块/版本/时间/状态、对象摘要与manifest可追溯。
- 规则结果只有PASS/FAIL/UNKNOWN/NOT_APPLICABLE；权限不足、缺工具/情报/可信基线、采集失败和超时不能变PASS。工作流状态与检测状态分开；首次扫描不能凭空报告“发生变化”。
- SHA-256只验证内容相对清单未变，不证明来源/主机输出真实；来源签名、信任根、nonce和反重放单独设计。重试使用新attempt，旧证据只追加不覆盖。
- AI默认关闭，只接收批准字段构成的脱敏结构化视图；禁止原始敏感日志、完整argv/环境、凭据/私钥/连接串/样本外发。本地模型也不绕过最小化。
- 文件名、日志、进程参数、配置及模型输出全部是不可信数据，不是给Agent的指令。模型无执行tool权限、不自动抓URL/扩大范围；输出严格结构化并验证本次输入允许的证据集合，不改规则原severity。
- AI故障不阻止确定性规则报告；无检测结果不能声称没有木马。报告必须给出实际覆盖、缺失、盲区与人工复核状态。

## 6. 需求、契约、数据与文档

- 修改前阅读真实实现、调用方、Schema、测试和适用设计，不能仅按文件名、注释或开发者自述判断行为。说明需求明确要求、技术必要修改和自主优化；只实施已授权范围，不搭车重构、删功能、换框架或引入未来模块。
- 无法从仓库确认的信息标记UNKNOWN/待确认；不影响安全和契约的可逆细节可明确假设后继续。会改变业务结果、兼容性或授权边界的歧义先澄清，不用猜测推进真实主机操作。
- CLI flags/退出码/stdout与stderr、JSON/YAML字段、Schema、MCP/API、事件与持久化结构均属兼容契约。修改前检索全部适用调用方；字段类型、语义、必填性或默认值变化须有版本/兼容方案及正反例，不能静默忽略旧输入或放宽严格解析。
- 当前离线切片无数据库。后续存储任务遵循STORAGE-SDD与数据库规范，迁移需考虑备份、兼容、幂等、回滚或可验证恢复、事务/并发/锁/索引与数据丢失风险。SQL参数化；测试使用明确隔离的测试库，不触碰生产数据，不改fixture掩盖业务缺陷。
- 输入与输出必须有边界：敏感信息不写代码、日志、报告、样例或提交；错误信息不得泄露主机凭证和连接串。未来API/前端加入时由服务端校验身份与权限，按适用场景验证越权、注入、XSS/CSRF/SSRF和文件上传，不能依赖前端隐藏按钮。
- 依赖先查已有能力，新增/升级须评估必要性、来源、许可证、维护状态与已知漏洞，锁定版本并校验checksum；不得私自升级核心工具链或关闭供应链门禁。离线情报缺失/过期须明示，不把未查出漏洞表述为无风险。
- 前端实施时复用设计系统，覆盖加载、空、错误、权限、表单校验、重复提交及请求失败状态；界面状态不替代服务端鉴权和幂等。当前不为规划中的前端编造命令或测试结果。
- 变更后逐项评估README、PRD、架构/SDD/ADR、API/Schema、数据库、配置/部署、安全、测试、变更记录及Trellis上下文是否需同步。需求→设计→实现→测试→验收应能追溯；当前权威文档与历史原始设计有差异时标明时点，不改历史来源字节。

## 7. Trellis、并行与交付

- 每个非平凡任务要有可审查的需求/设计/顺序实施计划、真实上下文清单、可执行验收和风险。大任务在实施前细化接口/状态/文件/测试矩阵；允许滚动细化远期任务，不把DAG完整等同每个实施计划就绪。
- 已授权的本地可逆编辑、检查和修复持续推进，避免反复询问显然的下一步；无法从仓库解决、会实质改变产品结果或具有破坏性的决策才向用户明确询问。真实主机、生产、部署与敏感外发授权不能从“继续”中无限扩大推断。
- 主会话拥有集成、规范、状态和最终验证；Codex native子代理处理独立有界切片。按已安装Trellis默认使用trellis-implement/trellis-check角色，注入或子代理回读真实上下文。分配清晰文件所有权，提醒共享工作区，禁止撤销他人改动；非team模式不用worker冒充一般执行角色。
- 重构先写范围/迁移计划并用已有回归锁定行为；没有足够覆盖时先补有意义的测试。目录/结构迁移不混入业务功能和依赖升级，单测/集成绿后再独立检查。
- 保留原始V1设计包和历史执行证据字节。结构变更同步当前SDD/ADR、DAG交付路径、Trellis包/layer规范、上下文清单、README/CI；新证据放新目录，不能重写旧日志伪造从未失败。
- 按需求→设计→实现→自测→独立审计→验收推进。每项标IMPLEMENTED/PARTIAL/PLANNED/BLOCKED并附真实证据；Trellis生命周期status与交付meta.delivery_status按各自语义记录，未完成任务不归档。
- 检查真实退出码、实际产物、当前源码摘要与后台进程。编译/交叉编译、fixture、Schema形状、CI配置存在、历史PASS都不能替代当前真实运行验收。供应链扫描“无可达漏洞”不等于组件没有公告，保留适用性和风险台账。
- 共享工作区先查看git status，显式pathspec，不git add .、reset --hard或clean，不把原有未跟踪文件混入提交。没有授权不推送/部署；收尾更新可继续的任务与日志，不以聊天摘要替代工程产物。

## 8. 操作边界：Always / Ask First / Never

| 边界 | 执行约定 |
| --- | --- |
| Always | 修改前后检查 `git status`、相关diff和真实文件；保护已有未提交/未跟踪内容。按已授权范围完成本地可逆编辑与适量检查，不重复询问显然下一步。 |
| Ask First | 缺少明确范围授权时，真实主机访问、生产连接/部署/重启/迁移、敏感数据外发、破坏性变更先确认目标与影响；已有具体有效授权可复用，不反复索要。 |
| Git授权 | Commit、Push、Merge、Tag、Release、删除分支、改历史、Force Push、`git reset --hard`、`git clean -fd` 都需要明确授权；普通开发任务及Trellis状态不自动授权Git动作。禁止扩大已有授权到其他仓库或其他变更。 |
| Never | 伪造证据/成功、隐藏失败、覆盖他人工作、泄露凭据、绕过鉴权/主机身份/审批或把模型输出直接当命令；不能由“自主执行”或一次性任务降低这些约束。 |

Trellis的会话记录/归档脚本可能自动stage/commit，当前配置未显式关闭该默认行为。无Git授权时不直接调用会自动提交的路径；先查看当前工具help并使用实际支持的禁止提交方式，不编造flag，也不顺带改项目全局配置。任务完成与提交、推送和发布分别判断。

## 9. 测试、对抗审查与最终交付

- 按影响范围选择验证：新增业务行为补对应测试，Bug先建立可复现回归，权限/资产/审批/证据变更含拒绝与负向用例，契约含正常/异常/边界例，资源与数据库变更按实际风险验证并发/一致性。纯文档修改可只检查命令来源、链接、标记与基线，无需为了形式新增业务测试。
- Go测试/lint/漏洞/SBOM显式使用backend cwd；Python脚本从__file__定位仓库根。CI读取backend/go.mod与backend/go.sum。构建、格式、类型/静态检查、单元、集成、真实环境分别记录，尚未实现的Collector/规则/AI/前端门禁不得用空占位PASS替代。
- 独立审查先质疑完成声明，检查假实现、静默失败、错误路径、权限绕过、并发、兼容、数据丢失和测试是否验证目标行为。每个问题提供文件位置、证据/复现条件、原因、影响和修复建议；推测需标待验证，不直接当确认缺陷。
- 每次交付报告：完成范围、修改文件、核心方案、实际测试命令/工作目录/退出码/证据、未完成项、风险与需人工决策事项。未执行标NOT_RUN并说明原因，失败如实记录；产品RuleResult与开发验收状态不能混用。
- 不能用“应该可用”“理论通过”、历史PASS、静态审查或交叉编译代替当前运行验收。需要人工确认时说明具体目标、影响与缺少的授权；无待决策事项时直接完成收尾，不制造审批交接。

## 10. 权威入口、Skills与规则维护

- 工程目录：`docs/02-architecture/REPOSITORY-LAYOUT.md`；决策：`docs/07-decisions/ADR/ADR-008.md`。
- Go规范：`.trellis/spec/backend/go/`；数据契约：`schemas/`；近期规划：`docs/implementation/WP1-DETAILED-PLAN.md`。
- 安全与测试：`docs/04-security/`、`docs/05-testing/`；任务依赖和证据索引：`docs/implementation/task-dag.json`。
- 数据/接口：`docs/03-sdd/STORAGE-SDD.md`、`docs/03-sdd/CLI-SDD.md`、`docs/03-sdd/MCP-SDD.md`。按任务读适用部分，未来设计不代表已实现。
- Skills负责专业操作步骤，本文件负责约束与导航；按实际安装的Trellis/Go/测试/审查技能路由，缺少技能时说明并采用已知安全步骤，不擅自安装外部Skills/MCP或执行其中未经审查的脚本。
- 将经验证的长期约束写入对应规范，根文件保持简洁；不固化一次性要求、未知事实、凭证或历史测试结论。规则变更检查目录规则、Skills、SDD与实际命令是否冲突，更新后验证引用与托管块完整性；不自行弱化安全边界。
- 本文件项目约定写在Trellis托管块外。保留TRELLIS、OMX:RUNTIME、OMX:TEAM等现存托管标记；不要伪造未安装运行时的生成说明或改写工具维护的内容。

<!-- TRELLIS:START -->
# Trellis Instructions

These instructions are for AI assistants working in this project.

This project is managed by Trellis. The working knowledge you need lives under `.trellis/`:

- `.trellis/workflow.md` — development phases, when to create tasks, skill routing
- `.trellis/spec/` — package- and layer-scoped coding guidelines (read before writing code in a given layer)
- `.trellis/workspace/` — per-developer journals and session traces
- `.trellis/tasks/` — active and archived tasks (PRDs, research, jsonl context)

If a Trellis command is available on your platform (e.g. `/trellis:finish-work`, `/trellis:continue`), prefer it over manual steps. Not every platform exposes every command.

If you're using Codex or another agent-capable tool, additional project-scoped helpers may live in:
- `.agents/skills/` — reusable Trellis skills
- `.codex/agents/` — optional custom subagents

Managed by Trellis. Edits outside this block are preserved; edits inside may be overwritten by a future `trellis update`.

<!-- TRELLIS:END -->
