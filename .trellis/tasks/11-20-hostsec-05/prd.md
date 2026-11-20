# HOSTSEC-05 — CLI生命周期与输出契约

日期2026-11-20；交付状态 **PARTIAL**。本次只细化规划，未声称新增业务实现或测试结果。目录契约统一为backend单Go module；所有路径均为仓库根相对路径。

## 目标与当前事实

- R05-1：参数/展示与领域用例分离，新增可用命令只通过明确用例调用，不允许参数绕过授权或任意Shell。
- R05-2：所有已实现命令具备帮助、单个JSON stdout、稳定错误码/非零退出与无敏感原文stderr；未实现命令不能返回成功占位。
- R05-3：取消/超时/输出失败可观测且有界；并发与timeout参数只传受控强类型值，当前离线plan不得宣称执行限额已强制。
- R05-4：任务查询、取消、历史、重试属于36/15等用例落地后的接入，当前仅冻结CLI适配契约，不造不存在的状态与扫描结果。

## 前置与输入

DAG前置：HOSTSEC-03, HOSTSEC-04。父子树不代表依赖；实现前读取其真实完成证据。部分任务已有03A贡献，不因此视为全项验收通过。

- `docs/03-sdd/CLI-SDD.md`
- `docs/03-sdd/DOMAIN-MODEL.md`
- `docs/02-architecture/REPOSITORY-LAYOUT.md`
- `docs/04-security/SECURITY-BOUNDARIES.md`

## 交付范围与所有权

实施时由单一任务负责人协调以下文件；共享文件（Schema、CLI、脚本、Makefile）与并行任务串行集成，不能互相覆盖：

- `backend/internal/cli/`
- `backend/cmd/hostsec/main.go`
- `schemas/doctor-v1.schema.json`
- `schemas/plan-v1.schema.json`
- `scripts/integration.py`
- `docs/03-sdd/CLI-SDD.md`

未来/尚不存在的交付文件在本PRD中是计划，不作为当前代码存在的证据。Go源码不回到仓库根；前端/常驻Agent/平台服务不以空工程形式凑交付。

## 验收矩阵

| 需求 | 真实进程/单元测试 | 负例与期望 |
|---|---|---|
| JSON/退出码 | version/assets/plan/doctor逐命令stdout/stderr独立解析 | 非JSON污染、secret回显、输出writer失败须非零 |
| 严格参数 | 已知FlagSet与目标互斥测试 | 未知flag、重复含冲突值、额外位置参数、裸IP/Shell参数拒绝 |
| context/timeout | 用例注入受控阻塞依赖，取消及deadline触发 | 不运行扫描来制造耗时；不得吞取消返回成功 |
| OS signal | 子进程测试程序使用同Run/Signal wiring与受控阻塞use-case，发送SIGINT/SIGTERM | 有界退出、无额外后续调用；不靠sleep碰运气 |
| Profile/资源 | 有界timeout/concurrency解析与计划描述 | 负数、0、溢出、非法单位、超策略上限拒绝 |
| 能力诚实 | 当前doctor不就绪、scan/status/report未实现 | 无Collector仍scan_ready=true或返回假scan_id即失败 |

## 不在本任务

生产或未授权主机连接、自动处置、任意Shell/SQL、安装扫描器或常驻Agent、外发敏感原文、未经授权远端发布均不在范围。未来依赖尚未实现的运行链路必须单独集成验收，不能用fixture或交叉编译替代。

## 风险与未决进入条件

新增通用flags可能被忽略或越过策略；shell signal测试易flake，需可控同步而非固定sleep；只验证Run预取消不等于真实执行器可取消。

未知若只影响未来真实部署则保留对应gate；若影响签名/身份/兼容等当前契约，先收敛设计再实现，不能由Agent猜测环境。
