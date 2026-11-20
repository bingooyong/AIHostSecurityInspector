# 仓库现状调查

日期：2026-11-20。状态：IMPLEMENTED（盘点）；业务平台尚未实现。

## 已核实的仓库状态

仓库路径为 `AIHostSecurityInspector`，分支 main，唯一历史提交 `3b04206 first commit`，只跟踪 README.md。现有 .agents/、.claude/、.codex/、.cursor/、.gitattributes、.trellis/、AGENTS.md、docs/ 在本轮开始前即为未跟踪文件，均按既有用户文件保留。不存在业务 Go 源码、go.mod、CI、规则实现、测试或可复用业务模块。仓库不是空目录，禁止重新初始化或覆盖 Trellis。

## Trellis

安装版本与 `.trellis/.version` 均为 **0.6.17**。已执行 get_context.py 的 current/phase/packages 路径，实际为单仓库、backend/frontend 两层。开发者 lvyong，现有 `00-bootstrap-guidelines` 为 in_progress，但本会话无当前任务。backend/frontend 是待填写模板，不能当成既有工程实践。任务工具实际支持 create、start、validate、add-context、add-subtask 等；不臆造命令。复杂任务使用 prd.md/design.md/implement.md 和两个非空 jsonl 上下文。父子关系不表示依赖，另建可校验 DAG。

## V1.0 来源

`docs/AI-Host-Security-Inspector-V1.0/` 已存在；逐份读取了全部 **22 个文件**（14 个顶层 Markdown、2 个 YAML、1 个 Schema、2 个 Skill、插件 README/JSON/MCP 示例）。没有缺失该 README 所列文件。另读 `docs/SKILL.md`。源文件逐文件摘要见 [manifest](implementation/v1-source-manifest.json)，保留原字节，修订采用独立基线和 ADR，不篡改来源文档。来源状态是方案，不是实现或检测证据。

## 开发环境（实测）

| 项目 | 结果 | 边界 |
|---|---|---|
| 操作系统 | macOS 26.6.2 / arm64 | 本机不是 Linux Collector 验收目标 |
| Go | go1.27.3 darwin/arm64 | 首轮最低构建版本暂定 1.27.3 |
| Git | 2.52.0 | 未提交本轮改动 |
| Python | 3.13.11；jsonschema 可导入 | 工程校验可用 |
| Trellis | 0.6.17 | 已初始化 |
| golangci-lint | 2.15.0，Go 1.27.2 构建 | 首轮运行后再报告结果 |
| govulncheck | 1.6.0，数据库日期 2026-11-11 | 可用不等于已通过 |
| Docker | client 29.1.2 / server 28.4.0 | 本轮不连接主机、不拉取 Collector 镜像 |
| cyclonedx-gomod | PATH 可用 | SBOM 待执行验证 |

## 缺失与非阻塞事项

企业试点主机、发行版、区域、负责人、SSH 指纹与账号、sudo 审查、生产窗口和数据外发审批尚未提供；它们阻止真实主机/生产验收，不阻止本轮离线工程初始化。样例仅使用 RFC 5737 文档地址。AI、数据库、SSH 和扫描器不会在本轮切片中启用。

## 一致性审查入口

见 [SOURCE-REVIEW](implementation/SOURCE-REVIEW.md) 及 ADR；本轮需求优先于 V1.0 中的可选/后续表述。
