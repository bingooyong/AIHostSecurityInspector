# HOSTSEC-42 技术设计

状态：本任务交付PARTIAL；以下新增契约与测试为计划。当前有效目录和依赖方向遵循REPOSITORY-LAYOUT及ADR-008。

## 当前基线与新module路径

已有root Makefile/verify/scripts和固定Action SHA，首切片本地门禁曾通过；这些证据只证明当时root module。当前目录迁移后setup-go读取backend/go.mod，cache-dependency-path为backend/go.sum；Go/golangci/vuln/SBOM命令明确cwd=backend，root脚本按__file__定位仓库与build。Go AST工具迁至backend/tools/check-boundaries，不为了方便保留root/scripts Go文件。

## Gate执行合同

每个GateResult为gate_id、command数组、cwd（repo相对）、tool_version或环境引用、started_at、elapsed、exit_code、status、log_path、input_hashes、artifact_refs、scope/limitations。状态至少区分PASS/FAIL/BLOCKED/NOT_IMPLEMENTED；命令退出0只是必要条件，gofmt有输出、产物缺失、Schema漏跑等语义仍失败。当前脚本若先失败停止，报告未执行后续项目，不能统一写PASS。

本地工具安装在repo/build/tools，版本固定，不能替换用户全局环境；错误工具链构建的分析器报错作为工具故障，重建后保留前一次失败并重跑。日志禁止原始敏感输入/环境/Token。源码摘要覆盖backend/cmd/internal/tools、go.mod/go.sum/lint和真实参与执行的根脚本/CI/Makefile；每次验证输出独立目录，迁移用layout-migration，历史bootstrap不能改路径或重写摘要。

## 门禁编排与供应链

依次校验目录/工具链、gofmt、vet/race/lint、AST/依赖边界、构建、真实CLI/Schema、DAG/文档来源、go mod verify、govulncheck、SBOM、双架构构建/manifest与摘要。依赖前置顺序不能并行产生stale binary。CI无必要写权限、不隐式推送部署；cache只加速不能代替go.sum/产物验证，upload artifact需只含允许日志/产物。

记录当前Go1.27.3标准库GO-2026-6859告警：当前CLI不导入net/http且无可达调用，不把退出0描述为所有module零漏洞；新增HTTP Provider/MCP/API前升级工具链并重扫。外部漏洞库不可访问是基础设施阻塞，不自动当无漏洞。工具和规则包许可/NOTICE/签名是进入Adapter发布的独立门禁，SBOM不能证明遵约。

## 逐阶段启用

规则17落地后逐规则正反/UNKNOWN/N/A成为必跑；证据16/18后篡改/跨scope；Collector/14/36后Linux双架构运行、SSH错key/权限/取消和只读差分；25–28后本地HTTP故障/脱敏/注入/ref；frontend任务34后真正独立前端job与Playwright。当前无对应程序则在coverage报告列PLANNED，不凭安装一个包或空test关闭MVP验收。

远端workflow运行需真实GitHub触发与run URL；本轮不为取得run记录擅自commit/push或发布。代码修改完成且本地全门禁通过可以标本地PASS，但42完整CI总验收应说明远端与后续运行门禁剩余项。

## 兼容、回滚与证据

CI配置与脚本按作用域小步回滚，保留每轮原始日志/hash；不能删失败日志来修复指标，旧cache不当可信来源，远端权限始终最小。

完成证据：docs/05-testing/evidence/hostsec-42：toolchain/命令cwd/退出、源码hash、各gate范围/未执行状态、SBOM/构建清单、失败分类负例及真实远端run URL（若未运行明确缺口）。 对应日志必须包含命令、工作目录、实际退出、输入/源码版本与验证范围；没有结果不写PASS。
