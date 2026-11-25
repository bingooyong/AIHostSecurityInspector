# CLI 详细设计

首切片：已实现，最终验证见执行报告；其余扫描相关命令 PLANNED。

## 已授权的首切片边界

Go工程位于backend/（根无go.mod），目录权威见REPOSITORY-LAYOUT。Go module `github.com/bingooyong/AIHostSecurityInspector/backend`，Go 1.27.4，std flag CLI；YAML 组织维护 `go.yaml.in/yaml/v4 v4.0.0` 为用户明确要求 YAML 解析所需唯一运行依赖，Schema 校验优先 Python jsonschema。CLI 仅解析参数和展示，backend/internal/asset 管资产、backend/internal/policy 管固定 Profile、backend/internal/planner 管授权计划。无 SSH、无执行器、无数据库、无模型调用。无需为未来模块制造空实现。

实现：`hostsec version [--json]`、`doctor [--json]`、`assets validate|list|snapshot --file PATH [--json]`、`assets diff --file PATH --against PATH [--json]`、`plan --file PATH (--host ID|--targets group:NAME) --profile NAME --dry-run [--json]`、`intent`（签名用执行意图，不执行）、`preflight`（复核当前资产快照与可选审批；默认不消费审批，`--consume` 需要 journal/ledger 且仍不把 execution_ready 设为 true）、`inspect-fixture`（合成根只读巡检）、`inspect-local`（单台已授权 loopback 实验室主机）、`inspect-authorized`（本轮 allowlist + 执行意图绑定 + SSH strict known_hosts/identity；本发行版仅 loopback 实验室目标，不是通用内网扫描器；成功采集仍为 PARTIAL，并在 `--out` 写入 `authorized-collection.json`；可选 `--intent-ledger` 在成功 prepare 后消费意图哈希以拒绝重放）、`mcp stdio`（本地10个业务工具，继承 `--principal`）、`api --listen 127.0.0.1:PORT`（loopback Web API）。帮助应展示实际已实现命令；未实现命令（含 `scan`、`mcp serve`）退出非零，不输出假成功。上述巡检/采集命令不得把 `collector_available`/`scan_ready`/`execution_ready` 设为 true。可选 `--timeout-seconds` / `--max-concurrency` 只约束本次 CLI 进程且不得放宽 Profile 上限。

每个命令独立 FlagSet；拒绝未知 flags、额外 positional、混合目标选择器、空组、未授权资产、未允许 Profile；不能接受裸 IP、网段、任意 SQL/Shell/路径作为扫描目标。assets list 仅展示 authorized=true，validate 允许存在未授权主机但缺失 authorized 必须失败。plan 在授权失败时不返回部分成功计划。

## 资产 v1（本切片严格子集）

根：`version: 1`、`hosts: []`、`groups: {name: {hosts: [host_id]}}`。Host 字段：host_id、hostname、addresses、platform=linux、architecture=x86_64|arm64、zone、environment=TEST|UAT|PROD、business_system、owner、criticality=low|medium|high|critical、authorized（必填 bool）、allowed_profiles、labels（字符串数组）、connection {transport: local|ssh, port, user, auth_ref, known_hosts_ref, host_key_policy: strict}。必填业务归属和架构等字段，SSH 必须有非 root 专用 user、port 1..65535、引用式认证与 known_hosts，绝不在配置接受密码、私钥或关闭主机校验。host_id/组名使用有界安全标识符且唯一。host_id不得为可解析IP地址；JSON/YAML显式null均拒绝。IP 为 net/netip 地址，不接受网段或 shell 字符；不解析 DNS、不连接地址。groups 引用必须存在，无重复 ID/成员/Profile。PROD 可被离线计划展示但不得由本切片执行。

严格限制文件 1 MiB、最多 1000 hosts、字符串/数组有界；显式 hosts: [] 合法（支持全未授权列表输出往返），缺失/null hosts 拒绝，空目标不能规划。ID/组名最多64 ASCII字符且首字符为字母或数字；认证引用最多128字符，hostname最多253字符。local连接可显式port:0与空认证引用。只接受一个 YAML/JSON 文档，拒绝 unknown fields、duplicate keys、YAML aliases、merge keys 和过深嵌套，错误不回显原输入或敏感值。JSON 同样拒绝重复 keys 和额外文档。实现应有针对性恶意输入测试。拒绝目录/命名管道等非普通文件以防阻塞。Schema assets-v1 与运行校验须一致，跨字段/跨记录关系由 Go 校验补充。

## Plan v1

字段：schema_version、mode=READ_ONLY、dry_run=true、profile、hosts（ID/地址/transport）、modules、tools、approval_required、execution_ready=false、limits、estimated_impact、limitations。四种固定 Profile，modules 显式列出累积集合：quick 的七模块；standard 加 package_inventory/vulnerability_correlation/baseline_assessment/targeted_file_scan；deep 再加 file_integrity/yara_scan/log_analysis；IR 为定向事件采集范围，不默认扩大 deep。deep/IR approval_required=true。plan 不接审批 ID，无审批也能规划，但永远不能标 ready；审批将绑定计划哈希、目标、策略、时间窗、执行人且启动前再次授权。当前 CLI 无 scan 命令。

limits 至少包含超时、并发、最大文件数/大小、路径白名单和排除项、IO 上限、资源压力停止、维护窗口要求；首切片仅展示固定安全默认，不声称限额已执行。默认不扫描 DB/备份/网络挂载，全盘 / 不允许。

## 输出/错误

stdout 只有命令结果，--json 输出可解析单个 JSON；结构化错误与日志在 stderr，不回显原文件或完整命令行。exit 0 成功/帮助；exit 2 参数/配置/授权拒绝；其他执行故障非零。doctor 只检查本机 OS/arch、版本、Collector 是否支持，Darwin 明确 Linux 采集不可用；环境不支持采集返回非零且不得说就绪。version/doctor 不读取凭据、不执行外部进程。取消用 signal.NotifyContext，当前解析/计划在 context 取消后退出。

## 验证

Go 单测资产重复/缺授权/strict host key/路径和目标注入/过大输入/别名/多文档，四 Profile、deep 审批需求、越权整组拒绝、未知 CLI flags、JSON stdout；构建 CLI 后进程级 smoke，用 Schema 校验正常输出和反例。交叉编译 Linux amd64/arm64 只证明构建。

## 本地 Ledger 持久化合同（2026-11-25 补强）

`--intent-ledger` 与 `--ledger` 的 JSON 字符串数组格式保持兼容。消费需持稳定 `.lock` 文件的非阻塞跨进程独占锁，在锁内重读当前状态、判断 replay、写同目录 0600 随机临时快照、fsync 文件、rename、fsync 目录后才返回成功。不使用 Open 时缓存决定消费，不提前把写失败的 nonce 留在内存。显式内存 Ledger 不提供跨进程或重启保障。

本用户私有、普通、单链接文件才可打开；最终 symlink/FIFO/过宽权限、损坏/null 和超过 1 MiB 状态拒绝，已观察存在的账本消失后该实例拒绝重建。锁忙立即拒绝，不阻碍无限期取消。所有消费者须使用同一私有本地目录与稳定路径，不得删除 lock 或恢复旧状态；缺失文件只用于初始化新账本，重启前丢失状态需要操作者核对，不能把重新初始化解释为原意图未消费。rename 后同步错误可能已提交，必须保守拒绝而非允许执行。账本不是审计 journal，不提供跨文件事务、NFS 分布式锁或对本机文件所有者的防篡改。
