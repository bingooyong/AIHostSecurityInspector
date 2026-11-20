# 多工程目录与协作规范独立审查

日期：2026-11-20。活动任务：hostsec-master。角色：独立Trellis check。审查结论：**未发现阻止当前目录迁移与AGENTS/spec更新验收的问题，没有需要自修的机械代码缺陷。** 此结论仅覆盖既有离线CLI的目录迁移、工程门禁、当前规范与WP1规划一致性，不表示MVP或未来运行控制已交付。

## 范围与实际读取

完整读取本次Trellis保存的hook上下文、master需求/设计/执行计划、AGENTS.md、backend/go规范、目录SDD、ADR-008、迁移计划；检查未跟踪的新文件，没有仅依赖git diff。追踪backend module/imports、源码/fixture与Go工具位置，root Makefile、Python验证和构建脚本、GitHub CI的cwd与cache、跨语言Schema和根样例位置、Trellis包/layer与48任务上下文路径，以及WP1的03/04/05/07/32A/42技术设计和实施顺序。

## 目录与行为复核

- 根目录无go.mod/go.sum/go.work、cmd/internal/pkg、Go源码或Go专用lint配置。10个Go源文件全部位于backend；module与项目imports统一为github.com/bingooyong/AIHostSecurityInspector/backend，Go工程辅助工具在backend/tools/check-boundaries。
- backend内Go测试的examples路径随目录层级调整，root CLI的显式--file语义未变化。Makefile用go -C backend或显式backend cwd，构建/SBOM统一输出repo/build；CI读取backend/go.mod和backend/go.sum。
- 本机重新执行11条冻结CLI行为用例，stdout/stderr/exit与迁移前逐字一致。当前doctor仍明确Collector不可用并exit1，plan仍execution_ready=false、limits.enforced=false；不存在空scan/report/MCP成功占位。
- 对跨环境比较分支作有界模拟，仅变化version.go_version与doctor.os/architecture/linux_platform_supported；11条用例通过明确的portable适配。同时模拟把计划execution_ready改true，比较正确失败。该模拟只证明比较器分支行为，不是真实Ubuntu/Linux运行验收。
- 已保存的Trellis托管块与当前AGENTS.md对应块逐字一致，标记各唯一且顺序正确；未写入伪OMX生成说明或模型表。项目约束位于托管块外，覆盖目录、安全、证据/AI、命令、协作和验收规则，没有把规划目录说成已运行前端/Agent工程。
- Trellis真实get_context输出backend包、go层和正确spec入口。全部48任务的implement/check.jsonl路径可解析；DAG/任务路径/交付状态校验通过。原V1 22文件以及bootstrap历史证据摘要复核未变。

## 规划一致性

WP1细化仍为7个活动任务/62项内部执行检查，不是新增62个Trellis任务。原任务的PARTIAL/PLANNED状态没有因文档细化变成IMPLEMENTED。

04先冻结纯ExecutionIntent与规范化hash；32A验证typed意图/签名/可信principal；07集成计划与Preflight，该依赖顺序没有新增32A与07的循环。32A早于完整SQLite时的跨进程锁、append-only journal、nonce消费与审计同一持久事件、崩溃失败关闭均被写成未来实现与测试门禁，未假称已运行。05明确真实status/retry/resume依赖15/36，当前不会创建假状态。03和42分别区分目录迁移与完整可复现发布/远端CI完成。

AGENTS、spec与目录SDD明确：单module/internal可见性不构成安全权限隔离；未来特权Collector须独立binary并验证传递依赖树，不导入模型Provider/API/MCP/数据库。常驻主机Agent与AI Agent接入材料明确分开，前端/常驻Agent未实施前不制造空工程。

## 独立执行结果

本代理执行并读取实际退出结果：

| 命令/校验 | 结果 |
|---|---|
| go -C backend test -race -count=1 ./... | PASS；4个业务包，入口/工具无测试文件明确显示 |
| go -C backend vet ./... | PASS；编译/类型检查通过 |
| backend cwd：golangci-lint run ./... | PASS；0 issues |
| python3 scripts/check_layout.py | PASS；目录边界与本机11条逐字行为 |
| python3 scripts/integration.py | PASS；27个真实CLI进程与资产/计划/doctor Schema |
| python3 scripts/contracts.py | PASS；未来结果契约正例及6反例，仅形状验证 |
| go -C backend run ./tools/check-boundaries | PASS；当前无任意执行或网络客户端imports |
| python3 scripts/validate_baseline.py | PASS；DAG、来源、上下文、文档、工程登记及历史摘要 |
| get_context.py --mode packages / task.py validate hostsec-master | PASS；backend/go入口和6条master上下文有效 |
| AGENTS Trellis块与保存原文比较 | PASS；逐字一致 |
| bootstrap历史摘要与源码迁移映射 | PASS；旧证据未改，原Go路径均映射backend |
| Python AST解析及git diff --check | PASS |
| portable比较器模拟及非法plan变化反例 | PASS；不冒充真实跨平台运行 |

主会话正式执行的[16项门禁结果](../05-testing/evidence/layout-migration/results.json)当前为PASS，本代理读取结果但未重写或冒称独立重跑所有供应链/跨构建门禁。旧bootstrap日志未被新verify覆盖。

## 未修复项与验收边界

没有未修复的本次目录/代码问题；本代理没有修改业务代码、任务状态、历史证据或他人文件，只写本独立审查记录。

真实远端GitHub CI、Linux Collector双架构运行、SSH认证/主机指纹、特权与只读前后快照、证据来源/篡改、AI/Skills以及资源守卫仍按任务PLANNED；当前交叉构建、Schema形状与模拟比较不证明上述运行控制。未来Approval的企业身份/密钥托管/目录权限依然是部署进入条件，不能凭自报字符串判断独立审批。供应链扫描已记录的Go标准库不可达公告不因此消失；新增HTTP能力前需按风险台账升级并重扫。
