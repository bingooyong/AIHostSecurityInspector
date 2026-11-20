# Monorepo 工程目录与依赖边界

日期：2026-11-20。用户修订：Go 源码、module 和 Go 专用配置不能置于仓库根目录；CLI、主机 Collector/Agent、服务端和前端应有明确工程边界。本文是当前权威目录契约，取代首轮根目录 Go module 方案；实际迁移验收见 layout-migration 报告。

## 仓库、module 与程序边界

仓库根负责跨工程协作：Trellis、文档、跨语言契约、版本化策略/规则、示例、集成、部署描述和构建调度。`backend/` 是 Go module 根，包含独立构建/部署的 CLI、Collector、Runner、MCP 与 API 入口；共用内部领域/应用服务，避免多个入口复制授权与检测逻辑。`frontend/` 为未来 React + TypeScript 独立工程。`integrations/` 为后续可分发 Skills、Agent 使用说明与 MCP 客户端模板；运行时检测逻辑留在 Go 内核。

Go 源码不能直接落在仓库根、根级 cmd/internal/pkg 或 root scripts 下。当前单 module 不引入 go.work，也不为目录隔离增加多套 go.mod/replace 或 GO111MODULE 开关。多可执行程序不要求多 module；未来独立发布/公开SDK/相互冲突依赖且有明确需求时另立 ADR 拆分。

Go module 路径为 `github.com/bingooyong/AIHostSecurityInspector/backend`；内部 import 同步增加 `/backend`。仓库的实际大小写保留，不为套用命名建议伪造不同 GitHub URL。对外包尚未发布，无旧 import 兼容承诺；未来模块 tag 若发布遵循 `backend/vX.Y.Z`。普通业务包采用短小、小写、职责命名，避免 utils/common 和没有消费者的 pkg 抽象。

## 目标目录（标注 future 的路径仅规划，不创建空工程）

```text
AIHostSecurityInspector/
├── backend/                     # 当前 Go module
│   ├── go.mod / go.sum
│   ├── .golangci.yml
│   ├── cmd/
│   │   ├── hostsec/              # 当前 CLI，薄 main
│   │   ├── hostsec-collector/    # future：Linux 固定只读采集入口
│   │   ├── hostsec-agent/        # future：若另立需求才引入常驻主机 Agent
│   │   ├── hostsec-api/          # future：Web API
│   │   ├── hostsec-mcp/          # future：MCP Server
│   │   └── hostsec-runner/       # future：区域执行节点
│   ├── internal/
│   │   ├── cli/                 # 当前 CLI 参数/展示
│   │   ├── asset/ policy/ planner/ # 当前资产与离线计划
│   │   ├── domain/ authorization/ approval/ # future 领域与权限
│   │   ├── orchestrator/ collector/linux/ transport/ tools/ # future 执行
│   │   ├── evidence/ rules/ findings/ report/ storage/ audit/ # future 检测证据
│   │   └── analyzer/ api/ mcp/ runner/ # future Provider/入口适配
│   └── tools/check-boundaries/   # 当前 Go AST 工程门禁
├── frontend/                    # future：package.json / src / tests，独立 TS 工程
├── integrations/                # future：Skills / MCP client 配置与文档
├── schemas/                     # 当前跨入口、跨语言 JSON Schema
├── examples/                    # 当前无害部署/配置输入示例
├── rules/ policies/             # future：独立版本规则包与策略，非 Go 源码
├── deploy/                      # future：批准部署配置，不自动部署
├── scripts/                     # 当前跨工程 Python/运维校验，无 Go 源码
├── docs/ .trellis/               # 当前设计、任务、证据与规范
├── .github/workflows/            # 当前 monorepo CI
├── Makefile                     # 当前根构建调度
└── build/                       # 当前忽略的统一产物与本地工具目录
```

`hostsec-agent` 的常驻主机进程与 Codex/Claude 等 AI Agent 是不同概念。MVP 采用一次性固定 Collector，用户列出 agent 工程不授权安装常驻 Agent。常驻主机 Agent 需后续独立需求、安全权限、升级/身份与资源设计；当前不创建空 main 或服务。AI Agent 仍通过 Skill/MCP 调用受控用例。

## 依赖方向与部署约束

- 每个 cmd 只装配实际需要的用例；CLI/MCP/API 复用授权、计划、编排、证据、规则与报告服务，不直接绕过访问 Collector。
- 特权 Collector 只依赖采集/受限工具和必要数据契约；禁止 import analyzer、模型/HTTP Provider、API/MCP、SQLite/平台存储与任意 Shell。同 module 不等于必须链接所有包；进入 Collector 任务时用 `go list -deps ./cmd/hostsec-collector` 建立并校验传递依赖 allowlist。
- Linux 平台文件/构建约束只留在 collector/transport 实现，domain/policy 不依赖 Linux syscall。Collector 不反向 import CLI，前端通过版本化 API/Schema 使用能力。
- 前端有独立 package.json、锁文件、lint/typecheck/test/build；在 WP7 实施前不创建空 npm 工程，后续 CI 单独 job。
- schemas 是机器契约来源；Go struct 与前端类型若生成应校验同步，不能再手写第二份无验证 Schema。样例/部署资源属于仓库根资源，运行时必须显式传入路径或受控打包，不能依赖进程 cwd 猜仓库位置。
- `.agents/skills` 等现有目录是开发工作流工具安装位置，不迁移或覆盖；产品 Skill 分发源在 integrations，正式安装仍遵循对应客户端约定。

## 构建、测试与路径语义

根 `make build/test/vet/lint/check/release` 调度 `backend/` module；直接 Go 命令使用 `go -C backend ...` 或 `cd backend`。根无 go.mod 时 `go test ./...` 不是合法项目验证命令，不用隐藏 module 补丁让它假成功。build/hostsec 与 Linux 产物路径、CLI flags、结果Schema保持不变。

Go 单元测试与源码同目录，静态模块fixture未来放各包 testdata；跨工程 CLI 样例仍在 examples，测试中相对路径必须随 backend 层级调整。Python scripts从自身路径求repo根；调用Go/供应链工具时显式cwd=backend，产物写repo/build。Lint配置归backend；setup-go读取 backend/go.mod，cache-dependency-path为backend/go.sum。

Trellis按实际0.6.17的package/layer规范注册backend包（path=backend），Go规范位于.trellis/spec/backend/go/，config.yaml的default_package为backend。原frontend模板仅保留为未来输入。未来前端落地时再注册frontend包和启用前端门禁，不能凭规划目录让Trellis报告已实现工程。任务DAG、活动任务交付路径/上下文同步新目录；提供的V1原始文档与历史原始执行证据按原字节保留，并明确它们描述旧目录时点。

## 迁移验收

1. 迁移前已有race测试通过，并冻结11条CLI进程行为输出/退出码；本次不修改产品行为或引入依赖。
2. Go源码/go.mod/go.sum/lint配置迁到backend，imports/测试fixture/Go工具路径一致；根无Go工程文件。
3. 构建、vet、race、lint、实际CLI/Schema、原始来源/DAG、无任意执行边界、模块校验、漏洞、SBOM、双Linux架构构建通过。
4. 前后CLI结果逐字一致（同工具链/同输入），从repo根与backend独立构建/测试均可运行。
5. 新门禁检测根目录Go文件/错误module/import/源码路径；验证历史来源和旧证据未修改。相同OS/架构/Go工具链严格逐字比较11条行为；其他环境只适配doctor平台字段及version.go_version，其余输出/退出保持一致并显式说明适配。
6. 迁移后的证据存 docs/05-testing/evidence/layout-migration，与首次bootstrap分开；远端CI和Linux实际Collector运行仍未验收。

## 官方依据

Go 官方的 module 布局、internal 访问规则、module 子目录路径与工作区规则见本轮 `docs/implementation/GO-LAYOUT-REFERENCES.md`。Go 并不强制此仓库采用 backend/frontend；这是用户多工程约束下的项目决定，采用 Go 内部的 cmd/internal 惯例实现。
