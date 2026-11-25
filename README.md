# AI Host Security Inspector · HostSec

企业主机智能安全巡检平台。专业工具负责发现，规则引擎负责判断，AI负责研判，证据负责证明，人负责最终决策。

当前交付：工程/安全/设计基线、离线 CLI，以及隔离环境内的 fixture 巡检、授权 loopback 采集、本地身份/MCP stdio、loopback API 与本地管理端。这些是 PARTIAL 可运行切片，不是通用内网扫描器，也不是企业主机扫描。`doctor`/`plan`/`inspect-fixture`/`inspect-local`/`inspect-authorized` 不得把 collector 或 scan 标成就绪。完整MVP必须六项全部验收。

## 运行

Go 1.27.4：

```sh
make build
./build/hostsec version --json
./build/hostsec assets validate --file examples/hosts.yaml --json
./build/hostsec assets list --file examples/hosts.yaml --json
./build/hostsec plan --file examples/hosts.yaml --targets group:pilot --profile quick --dry-run --json
./build/hostsec plan --file examples/hosts.yaml --host linux-test-001 --profile deep --dry-run --json
./build/hostsec doctor --json
./build/hostsec inspect-fixture --file examples/hosts.yaml --host linux-test-001 --root <ABS_FIXTURE> --out <ABS_OUT> --profile quick --json
./build/hostsec inspect-authorized --file examples/lab-localhost.yaml --allowlist examples/lab-allowlist.yaml --bindings examples/lab-bindings.yaml --intent-file <ABS_INTENT> --out <ABS_OUT> --profile quick --json
./build/hostsec mcp stdio --file examples/hosts.yaml --identities examples/identities.json --principal operator-alice
./build/hostsec api --listen 127.0.0.1:18080 --file examples/hosts.yaml --identities examples/identities.json
```

`doctor` 明确 Collector 未实现、scan_ready=false，并退出1；这不是扫描失败假绿。四种Profile均为离线描述，plan始终execution_ready=false、limits.enforced=false。deep/IR展示审批要求；本地审批工作流仍不是平台审批。样例只含文档地址，不连接目标。`scan` 与 `mcp serve` 仍被拒绝。`inspect-authorized` 只采集操作者在本轮 allowlist 中明确点名、并与执行意图绑定的主机；本发行版这些目标必须是 loopback 实验室监听或本机实验室文件系统，不能用来扫描内网地址。实验室采集即使模块全部成功也保持 PARTIAL，并在 `--out/authorized-collection.json` 写出聚合摘要；`--intent-ledger` 可在成功 prepare 后消费意图哈希以拒绝重放。`mcp stdio` 继承 `--principal`，请求 JSON 不能自报角色。API 只绑定 loopback，身份来自 `X-HostSec-Principal` 且必须存在于本地 identities。

资产支持严格单文档YAML/JSON，最大1MiB/1000主机；显式授权、Profile白名单、稳定且非IP的host_id、strict host key与认证引用。未知/重复/空值/别名/多文档/非普通文件会被拒绝。分组混合未授权主机会整体拒绝。原V1示例含未实现字段，故当前可运行严格样例位于examples/hosts.yaml；不静默忽略来源字段。空授权列表可展示，空目标不可计划。

### 本地防重放账本

`--intent-ledger <ABS_LEDGER>`（以及使用同一 Ledger 的 `--ledger`）应置于操作者拥有的私有本地目录（0700），文件须为本用户拥有的 0600 普通单链接文件。首次可不存在，已有 JSON 字符串数组无需迁移。所有消费者必须指定同一路径；程序会保留 `<ABS_LEDGER>.lock` 侧车，以跨进程锁、锁内重读、同步原子替换保护消费。锁忙立即拒绝，不会无限等待。账本最大 1 MiB，损坏、null、超限、symlink、FIFO 或过宽权限均失败关闭。

不要删除/替换 `.lock`，不要回滚/清空账本来重试。写失败不先消耗内存 nonce；原子替换后的目录同步错误则可能已经消费，必须按已消费处理并人工核对，不能为了重试恢复旧文件。输出失败或后续取消不会退还已消费意图。备份/恢复须停用所有消费者并保留整个目录；该本地账本不是审计 journal，也不保证两个独立文件的跨资源事务，不支持把 NFS/多节点共享文件系统当分布式防重放服务，不能防御可任意改写目录的本机所有者。

## 开发验证

```sh
python3 -m pip install -r scripts/requirements.txt
make tools
make check
```

工具装到build/tools，不替换用户全局工具。验证包括格式、vet、race、lint、CLI/Schema、安全边界、DAG/来源/链接、漏洞、SBOM及Linux双架构构建。CI已配置，远端尚未执行；Linux交叉编译仅证明构建，Collector双架构运行仍待实现与测试。未来结果Schema的正反样例只验证契约形状，不是扫描/证据/AI运行验收。

## 工程入口

- [本轮执行报告](docs/implementation/BOOTSTRAP-REPORT.md)、[验收结果](docs/05-testing/ACCEPTANCE-RESULTS.md)、[对抗审计](docs/security/ADVERSARIAL-REVIEW.md)
- [仓库盘点](docs/00-project-inventory.md)、[来源审查](docs/implementation/SOURCE-REVIEW.md)
- [产品需求](docs/01-product/PRD.md)、[MVP实施计划](docs/implementation/MVP-PLAN.md)
- [系统架构](docs/02-architecture/SYSTEM-ARCHITECTURE.md)、[CLI契约](docs/03-sdd/CLI-SDD.md)、[领域模型](docs/03-sdd/DOMAIN-MODEL.md)
- [安全边界](docs/04-security/SECURITY-BOUNDARIES.md)、[威胁模型](docs/04-security/THREAT-MODEL.md)、[数据治理](docs/04-security/DATA-GOVERNANCE.md)
- [48节点任务DAG](docs/implementation/TASK-DAG.md)、[机器DAG](docs/implementation/task-dag.json)、[ADR](docs/07-decisions/ADR/)
- [工具官方资料核查](docs/implementation/TOOL-EVALUATION.md)、[测试策略](docs/05-testing/TEST-STRATEGY.md)、[验收标准](docs/05-testing/ACCEPTANCE-CRITERIA.md)

## 目录与后续

Go工程已独立放在backend/，module路径为github.com/bingooyong/AIHostSecurityInspector/backend。根目录不放go.mod、Go源码或Go专用lint配置；根Makefile统一调度。直接Go命令用go -C backend，跨语言Schema/示例/脚本保留仓库级位置。

```text
backend/       Go module：cmd/多binary入口、internal/共享内核、tools/Go门禁
frontend/      本地React/TypeScript控制台（PARTIAL，非企业部署）
integrations/  规划：产品Skills、MCP客户端接入材料
schemas/       跨语言版本契约
examples/      无害配置示例
scripts/       跨工程验证脚本
```

backend/cmd/hostsec当前已实现本地 CLI/MCP stdio/loopback API 装配；Collector、区域 Runner、常驻主机 Agent 仍无企业入口。常驻主机Agent与AI Agent分开；当前仍不安装常驻Agent。单Go module无需go.work，各binary只装配自身依赖；特权Collector后续须校验不依赖模型/数据库的窄依赖树。

[目录迁移与AGENTS报告](docs/implementation/REPOSITORY-LAYOUT-REPORT.md) · [工程目录契约](docs/02-architecture/REPOSITORY-LAYOUT.md) · [目录决策ADR-008](docs/07-decisions/ADR/ADR-008.md) · [WP1详细计划](docs/implementation/WP1-DETAILED-PLAN.md)

工程约束入口为AGENTS.md和.trellis/spec/backend/go/；Trellis已注册backend与frontend包。frontend规范层描述本地控制台，不是生产UI验收。

下一交付为MVP-1剩余契约与调度前置，再依DAG推进Linux采集/证据/规则/报告端到端。SSH、审批、可信基线、资源守卫与授权复核均须在对应扫描上线前通过测试。MCP/区域Runner为WP6，API/Web为WP7。

默认READ_ONLY；不自动处置、不任意Shell、不探测未授权IP、不关闭SSH主机校验、不外发敏感原始日志。没有命中规则不代表绝对没有木马。真实企业主机/权限/窗口/外发政策尚未提供，本轮不部署、不发布、不连接生产。
