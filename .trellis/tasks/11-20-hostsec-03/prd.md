# HOSTSEC-03 — Go 工程、构建与发布骨架

日期2026-11-20；交付状态 **PARTIAL**。本次只细化规划，未声称新增业务实现或测试结果。目录契约统一为backend单Go module；所有路径均为仓库根相对路径。

## 目标与当前事实

- R03-1：Go module、源码和Go专用配置位于backend，根保留多工程调度；CLI、一次性Collector、API/MCP/Runner各自有未来cmd入口边界，前端和集成不混入Go源码。
- R03-2：保持首切片命令、参数、JSON、退出码和build/hostsec产物位置；目录迁移不能改变授权或只读行为。
- R03-3：版本、工具链、模块依赖、目标OS/架构、构建参数和二进制SHA-256可追溯；版本注入不依赖目标机Git或网络。
- R03-4：批准的同输入/同工具链/同目标/同版本元数据可重复构建；构建结果与真实运行验收分别记录。
- R03-5：只发布已实现程序，不生成空Collector/Agent/API二进制；本任务不自动发布GitHub release、推送或部署。

## 前置与输入

DAG前置：HOSTSEC-03A。父子树不代表依赖；实现前读取其真实完成证据。部分任务已有03A贡献，不因此视为全项验收通过。

- `docs/02-architecture/REPOSITORY-LAYOUT.md`
- `docs/07-decisions/ADR/ADR-008.md`
- `docs/03-sdd/CLI-SDD.md`
- `docs/06-operations/DEPLOYMENT.md`
- `docs/implementation/LAYOUT-MIGRATION-PLAN.md`

## 交付范围与所有权

实施时由单一任务负责人协调以下文件；共享文件（Schema、CLI、脚本、Makefile）与并行任务串行集成，不能互相覆盖：

- `backend/go.mod`
- `backend/go.sum`
- `backend/.golangci.yml`
- `backend/cmd/hostsec/main.go`
- `backend/tools/check-boundaries/main.go`
- `Makefile`
- `scripts/build_release.py`
- `scripts/check_layout.py`
- `docs/06-operations/DEPLOYMENT.md`

未来/尚不存在的交付文件在本PRD中是计划，不作为当前代码存在的证据。Go源码不回到仓库根；前端/常驻Agent/平台服务不以空工程形式凑交付。

## 验收矩阵

| 判据 | 自动化或人工证据 | 失败判定 |
|---|---|---|
| backend独立module和根无Go工程 | 目录门禁、go list -m、root Makefile与backend直接go test | 根go.mod/go.work、旧import、Go工具仍在root/scripts即失败 |
| 迁移不改行为 | 冻结的11条CLI stdout/stderr/exit与迁移后逐字比较 | 任一差异需解释并回归，不能自动更新golden掩盖 |
| 版本注入 | 默认dev版本、显式版本两套真实version命令；manifest同版本 | 版本未注入、空值/非法值、manifest与binary不一致即失败 |
| 产物与重复性 | Linux amd64/arm64 ELF头/架构、两次干净输出目录同hash | 任一缺产物、错架构、hash差异或依赖变更即失败 |
| 发布元数据 | SBOM、依赖校验、工具链/flags/dirty状态、hash清单 | 未记录工作区dirty或引用不存在提交即失败 |
| 构建/运行分离 | 报告标CROSS_BUILD_ONLY；本机CLI运行记录 | 把交叉构建标成Linux采集验收即失败 |

## 不在本任务

生产或未授权主机连接、自动处置、任意Shell/SQL、安装扫描器或常驻Agent、外发敏感原文、未经授权远端发布均不在范围。未来依赖尚未实现的运行链路必须单独集成验收，不能用fixture或交叉编译替代。

## 风险与未决进入条件

工作区原本含未跟踪用户文件，禁止git clean/reset；新目录可能造成fixtures、SBOM/CI缓存和hash清单失联；同module不能代替特权边界。

未知若只影响未来真实部署则保留对应gate；若影响签名/身份/兼容等当前契约，先收敛设计再实现，不能由Agent猜测环境。
