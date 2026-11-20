# CLI 首切片独立审查

日期：2026-11-20。任务：HOSTSEC-03A。角色：独立 Trellis check。审查结论：本切片发现的两项契约问题均已由原实现代理修复，并经独立复验；当前没有阻止离线 CLI 切片验收的未修复问题。此结论不代表主机扫描平台或首期 MVP 全部完成。

## 审查范围与方法

读取活动任务的 PRD/design/implement、完整 hook 上下文及其 backend 规范，检查未跟踪的新文件，未仅依赖 git diff。范围包括 cmd/、internal/、Go 依赖、资产/计划/doctor Schema、无害样例、测试、工程门禁及 CI 调用关系；scan-result Schema 仅按未来形状契约审查。

实际追踪资产文件读取与解析、主机/组选择、授权与 Profile 白名单、计划构造、stdout/stderr、退出码及 doctor 的非就绪状态。检查 YAML/JSON 多文档、重复键、未知字段、别名/merge、深度/字节/主机数限制、非普通文件、缺授权、混合越权组、非法目标及命令 flag。当前无 SSH、扫描执行器、模型请求或处置接口，不能把这些未来能力的缺失算成本切片漏洞，也不能据此声称未来运行安全验收通过。

## 发现与修复

### CR-01：显式 null 被解码为 local 连接字段零值

风险：低，严格输入/Schema 契约偏差；本切片没有执行器，未形成远程命令执行或越权扫描。

修复前复现：在有效 JSON 资产的 local connection 中加入 `port: null`、`user: null`、`auth_ref: null` 或 `known_hosts_ref: null`。encoding/json 将其解码为零值，Go validate 返回成功，但 assets Schema 拒绝 null。YAML 的同类 null 也需要一致拒绝。

影响：资产校验与外部 Schema 判断不一致，可能让下游误以为存在明确的合法标量配置。

建议/修复：解析阶段显式拒绝 null。原实现代理已在 `internal/asset/asset.go:216` 的 JSON token 预检及 `internal/asset/asset.go:255` 的 YAML node 检查中拒绝 null，而不是依赖解码后零值校验。

回归：`internal/asset/asset_test.go:187` 的 TestRejectNullConnectionScalars 覆盖四个字段的 JSON/YAML 共八个用例。独立使用修复后的 build/hostsec 复验四个 JSON 用例：全部 exit 2、stdout 为空，assets Schema 同样拒绝。

状态：IMPLEMENTED（修复与复验）。

### CR-02：IP 字符串可作为稳定 host_id

风险：中，主机身份契约偏差；修复前仍须资产登记并授权，不是未授权任意地址扫描。

修复前复现：把授权主机 host_id 与组引用同时设成 `192.0.2.10`，执行 `plan --host 192.0.2.10 --dry-run --json`，原版本 exit 0。原通用 ID 字母表允许该字符串，使其与“不以 IP 为主机唯一标识、不接受裸 IP 目标”的契约冲突。

影响：稳定主机身份可能退化为地址标识，后续资产漂移与身份核验容易混淆。

建议/修复：把稳定主机标识校验与通用组名校验分离。原实现代理已增加 `internal/asset/asset.go:73` 的 ValidHostID，以 netip.ParseAddr 排除真实地址，并由 Inventory.Validate 验证所有主机；资产与计划的 host_id Schema 同步排除 IPv4 地址。组名的既有字母表不必因此改变。

回归：`internal/asset/asset_test.go:223` 的 TestHostIdentityCannotBeIPAddress 包含 IPv4/IPv6、非地址标识、直接领域校验、JSON/YAML，以及同步修改组引用的负例，避免用悬空引用假证明修复。独立以修复后 CLI 复验登记的 IP 形 host_id：资产校验 exit 2、stdout 为空，assets Schema 同样拒绝。

状态：IMPLEMENTED（修复与复验）。

## 验证结果

本代理独立执行并读取结果：

- `go test -race -count=1 ./internal/asset ./internal/planner ./internal/cli ./internal/policy`：PASS。
- `go vet ./...`：PASS；Go 编译/类型检查由测试与 vet 路径通过。
- `golangci-lint run ./...`：PASS，0 issues。
- 修复前执行 `scripts/integration.py`：27 个真实 CLI 进程及资产/计划/doctor Schema 检查 PASS；发现的边界用例另行加入上述回归。
- 修复后独立进程复验：四个 null local 连接标量与一个登记 IP 形 host_id，五项均 CLI/Schema 拒绝。
- `scripts/contracts.py`：未来结果形状正例与六个反例 PASS；不证明真实证据存在、引用成员关系、来源真实性或实际采集。
- `scripts/validate_baseline.py`、`go run ./scripts/check-boundaries`、`go mod verify`：PASS。

主会话统一执行的最新完整 13 门禁结果见 [results.json](../05-testing/evidence/bootstrap/results.json)，包括格式、vet、race、lint、边界、CLI 构建/集成、Schema、基线、漏洞、SBOM、双架构构建和空白。该文件是主会话的正式证据，本代理没有重写日志或假称独立重跑全部供应链/构建门禁。曾有本地旧工具链不兼容问题，由主会话重建仓库本地工具后复跑，不把第一次失败隐藏为成功。

## 适用范围与余项

本切片只有离线计划，固定 `execution_ready=false`、`limits.enforced=false`；doctor 明确 Collector 不可用并返回非零。构建 Linux amd64/arm64 不等于 Linux 运行或 Collector 验收。资产 authorized 是受控本地清单声明，不等于平台 RBAC；未来执行仍须服务端身份/授权复核和可验证审批。

未发现本切片存在任意 Shell、SSH trust bypass、未授权目标执行、模型敏感外发或自动处置入口。AST import 门禁是当前切片的辅助检查，不能替代未来实际执行路径审计。SSH、规则/证据真实性、AI 注入/脱敏、资源限额执行、区域隔离、MCP 权限和真实主机只读前后快照仍按 DAG 对应任务为 PLANNED；无生产/未授权主机连接，也未运行真实恶意样本。

本代理未修改产品代码、任务状态或他人文件；仅编写本独立审查记录。当前没有额外未修复的切片内发现。
