# HOSTSEC-42 — 跨工程CI与供应链门禁

日期2026-11-20；交付状态 **PARTIAL**。本次只细化规划，未声称新增业务实现或测试结果。目录契约统一为backend单Go module；所有路径均为仓库根相对路径。

## 目标与当前事实

- R42-1：CI和本地入口从backend独立module运行Go校验，同时覆盖根级Schema/示例/文档/DAG；禁止根Go工程回归。
- R42-2：格式/vet/lint/race/CLI集成/Schema/安全边界/模块依赖/漏洞/SBOM/双架构构建/产物完整性均有真实退出证据，缺工具/网络故障不得伪绿。
- R42-3：执行日志记录命令、cwd、版本、退出码/耗时与产物hash，旧bootstrap原日志不覆盖；本地通过与远端CI运行分开。
- R42-4：规则、Collector、SSH、AI、Web门禁随模块落地变为必跑；未实现模块标NOT_IMPLEMENTED/PLANNED，不用占位测试声称通过。
- R42-5：Action SHA和工具/依赖版本固定，CI只读contents、避免凭据泄漏；告警按可达性和例外台账处理，不能将SBOM等同安全证明。

## 前置与输入

DAG前置：HOSTSEC-03A。父子树不代表依赖；实现前读取其真实完成证据。部分任务已有03A贡献，不因此视为全项验收通过。

- `docs/05-testing/TEST-STRATEGY.md`
- `docs/05-testing/ACCEPTANCE-CRITERIA.md`
- `docs/02-architecture/REPOSITORY-LAYOUT.md`
- `docs/implementation/TOOL-EVALUATION.md`
- `docs/04-security/SECURITY-BOUNDARIES.md`

## 交付范围与所有权

实施时由单一任务负责人协调以下文件；共享文件（Schema、CLI、脚本、Makefile）与并行任务串行集成，不能互相覆盖：

- `.github/workflows/ci.yml`
- `Makefile`
- `scripts/verify.py`
- `scripts/check_layout.py`
- `scripts/build_release.py`
- `scripts/integration.py`
- `scripts/contracts.py`
- `scripts/validate_baseline.py`
- `backend/tools/check-boundaries/main.go`
- `scripts/requirements.txt`

未来/尚不存在的交付文件在本PRD中是计划，不作为当前代码存在的证据。Go源码不回到仓库根；前端/常驻Agent/平台服务不以空工程形式凑交付。

## 验收矩阵

| 门禁 | 实际对象 | 失败/未知处理 |
|---|---|---|
| 目录/构建 | 根无Go module/源码、backend module/import、root与backend入口 | 旧路径/空工程/错误cwd失败 |
| 格式/静态/测试 | backend全部实际Go包，包含Go工具与现有边界负例 | 没有测试或未覆盖模块不得当功能验收 |
| CLI/Schema | 构建后真实进程、合法与非法Schema输入、未来契约形状分开 | stdout污染、未知字段/类型/关系被漏验，分别标注 |
| 供应链 | go mod verify、govulncheck、SBOM、固定版本与许可记录 | reachable漏洞失败；仅module告警明确台账，不隐瞒；网络故障非安全通过 |
| 产物 | 二进制ELF架构/hash、manifest/SBOM引用当前源码 | 错架构/缺产物/hash不符失败，交叉构建不算运行 |
| 运行安全 | 模块实现后无害Linux/SSH/AI/规则/篡改测试 | 未实现明确PLANNED；实际需要的集成环境不可用为BLOCKED |
| 远端CI | GitHub job实际run URL、commit/source和结果 | 只有workflow文件不能标远端PASS |
| 前端 | frontend真正落地后的TS lint/typecheck/test/build与Playwright | 当前无前端不创建空package.json或成功占位job |

## 不在本任务

生产或未授权主机连接、自动处置、任意Shell/SQL、安装扫描器或常驻Agent、外发敏感原文、未经授权远端发布均不在范围。未来依赖尚未实现的运行链路必须单独集成验收，不能用fixture或交叉编译替代。

## 风险与未决进入条件

当前源码和旧binary/日志混淆、缓存隐藏依赖漂移、网络工具不可用假绿、只记录CI配置不运行、未来空模块填充覆盖率均属实质风险。

未知若只影响未来真实部署则保留对应gate；若影响签名/身份/兼容等当前契约，先收敛设计再实现，不能由Agent猜测环境。
