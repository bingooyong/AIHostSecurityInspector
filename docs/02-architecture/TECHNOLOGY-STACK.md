# 技术栈与依赖门禁

设计基线 0.1，2026-11-20。本文件确定分期选型，不能用来证明依赖或 Adapter 已实现。官方版本、维护状态、许可证、架构证据与访问来源见 [TOOL-EVALUATION](../implementation/TOOL-EVALUATION.md)。

## 1. 首切片

| 项目 | 决定 | 实施约束 |
|---|---|---|
| 语言/模块 | Go 1.27.3；`github.com/bingooyong/AIHostSecurityInspector/backend` | Go module位于backend/，module path含/backend；checksum固定；跨平台控制端不表示跨平台 Collector |
| CLI | 标准库 flag | 每命令独立 FlagSet；不增加 Cobra 等本轮不必要依赖 |
| YAML | `go.yaml.in/yaml/v4 v4.0.0` | 严格字段、唯一键、输入大小/深度/别名边界；JSON 同样严格 |
| JSON | 标准库 encoding/json | 单文档、结构化结果；关系约束须由领域校验补充 |
| Schema | JSON Schema 2020-12 | schema_version 固定；Python jsonschema 用于工程验证，不成为目标主机运行依赖 |
| 日志 | Go 结构化日志机制 | stderr，与 stdout JSON 分离；不输出密钥与原文配置 |
| 测试 | go test / race / vet / golangci-lint | 测真实行为与失败边界；fixture 无害、脱敏 |

本轮不为设计接口安装 SQLite、SSH、模型 SDK、MCP SDK 或扫描器；不用 Kafka、Kubernetes、Redis、多 Agent 运行框架建立最初链路。

## 2. 后续确定方向与待验证选项

| 范围 | 方向 | 实现前门禁 |
|---|---|---|
| CLI 存储 | SQLite + 受控本地文件 | 优先评估纯 Go `modernc.org/sqlite`；驱动依赖匹配、双架构构建、事务/并发/崩溃恢复测试后再固定版本 |
| 平台存储 | PostgreSQL + MinIO/S3 兼容对象存储 | 数据迁移、RBAC、加密/备份/隔离测试；不自动连接外部数据库 |
| SSH | OpenSSH 固定 Collector 通道为 V1.0 方向 | 固定程序、strict known_hosts、关闭不受控用户配置/转发/代理命令；若换 Go SSH，需 ADR 与认证/指纹/超时回归 |
| 规则 | Go + YAML 声明式有限谓词 | 不引入 eval、脚本插件或任意表达式执行器；规则包与代码独立版本 |
| AI | 统一 Provider，OpenAI/兼容 API/本地服务 | 外发策略、TLS/端点、脱敏、结构化输出、超时/重试/引用校验；直接 HTTP 或 SDK 的选择留实现任务核实 |
| MCP | Go，业务级工具 | 协议版本/官方 SDK 届时核实并固定；不可在未实现前发布活跃 endpoint |
| Web | Go API + React/TypeScript | WP7 再建立框架与前端依赖；Web 共用应用服务 |
| PDF/HTML | 后续报告呈现器 | 不进入首期 JSON/Markdown 验收；渲染沙箱和转义测试另立任务 |

## 3. 专业工具组合

P0 优先 osquery 和 Lynis；P1 OpenSCAP、ClamAV、YARA；P2 才评估 Velociraptor、Wazuh、Falco。原生 Collector 提供不依赖外部工具的端到端基础链路，专业工具补充覆盖，不复制病毒引擎、SCAP 评估或大型 SIEM。

每个工具按**固定版本**审查许可证、子组件、规则/病毒库/SCAP 内容的独立条款，再确定内部使用、修改、分发或商业集成义务。上游支持 Linux ARM64 不是 HostSec 的 ARM64 验收；本项目必须实跑目标 OS/架构/最小权限矩阵。

osquery 仅固定 SQL/query ID，不能接受用户 SQL 或 meta commands。Lynis 本身会写日志和报告，限定批准输出目录并审查测试副作用。OpenSCAP 拒绝 remediation 和自动拉远程资源；ClamAV 禁止删除、移动、复制命中项，扫描不自动更新签名库。YARA 上游维护状态与 YARA-X 候选评估分开，不能擅自替换契约。Wazuh 必须区分固定 release 与 main 的许可证，且禁用 active response。

## 4. 供应链与发布

依赖采用精确版本、go.sum 校验、许可证记录和漏洞扫描。发布包含 SBOM、源码版本、构建工具链、目标平台、可执行文件 SHA-256、规则/内容包摘要与签名。没有本地或 CI 执行记录不能声称门禁通过。离线构建在批准联网区准备并验证依赖，目标扫描主机不联网下载或安装软件。

新依赖必须有实际任务需求；纯接口设计不构成安装依赖的理由。重大换型通过 ADR 记录原设计、原因、影响和回归测试。数据格式和 Provider 接口先固定行为，避免将单个第三方 SDK 类型传播至领域层。
