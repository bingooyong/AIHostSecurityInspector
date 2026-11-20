# 05. CLI、MCP、Skills 与插件接口规范

## 1. CLI 命令

```text
hostsec version
hostsec doctor
hostsec assets validate --file hosts.yaml
hostsec assets list
hostsec plan --targets group:pilot --profile quick --dry-run
hostsec scan --targets group:pilot --profile quick
hostsec scan --host host-prod-app-001 --profile deep --approval-id SEC-APPROVAL-001
hostsec status --scan-id SCAN_ID
hostsec findings list --scan-id SCAN_ID
hostsec evidence show --evidence-id EVIDENCE_ID
hostsec analyze --scan-id SCAN_ID --provider openai
hostsec report --scan-id SCAN_ID --format md|html|json
hostsec rules validate --dir ./rules
hostsec rules test --dir ./rules --fixtures ./testdata
hostsec bundle export --scan-id SCAN_ID
hostsec bundle import --file result-bundle.tar.zst
hostsec mcp serve
```

### 命令约束
- `plan` 默认不连接主机，只校验授权和生成执行计划。
- `scan` 只能调用 Profile 中定义的模块。
- `deep` / `incident-response` 必须带有效审批 ID。
- 不提供 `--command`、`--shell`、`--exec` 等任意命令参数。
- 不允许将 SSH 密码或私钥作为命令行参数。
- 所有扫描支持 timeout、max-concurrency、rate-limit。
- 结果写入受控目录，文件权限限制为执行用户。

### 示例
```bash
hostsec doctor
hostsec assets validate --file ./hosts.yaml
hostsec plan --targets group:pilot --profile quick --dry-run
hostsec scan --targets group:pilot --profile quick --max-concurrency 2
hostsec scan --host host-prod-app-001 --profile deep --approval-id SEC-APPROVAL-001
hostsec report --scan-id SCAN_ID --format md
```

## 2. 资产和策略配置
主机资产见 `examples/hosts.example.yaml`；巡检策略见 `examples/policy.example.yaml`。配置中不保存密码、私钥和 API Key。认证从 SSH Agent、环境变量或密钥管理服务获取。

## 3. MCP Server

### 3.1 原则
MCP 只暴露业务级受控能力，不暴露通用 Shell、SSH exec 或文件写入。

### 3.2 工具
| Tool | 参数 | 用途 |
|---|---|---|
| `list_authorized_hosts` | filter | 查询当前调用者授权主机 |
| `plan_host_scan` | targets, profile | 生成 dry-run 计划 |
| `request_scan_approval` | plan_id, reason | 发起审批 |
| `run_host_scan` | plan_id, approval_id? | 执行已授权计划 |
| `get_scan_status` | scan_id | 查询任务 |
| `list_findings` | scan_id, severity? | 查询发现项 |
| `get_evidence_metadata` | evidence_id | 查看证据元数据 |
| `analyze_scan_findings` | scan_id, provider? | 分析脱敏发现项 |
| `generate_scan_report` | scan_id, format | 生成报告 |
| `list_scan_profiles` | 无 | 查看允许 Profile |

禁止提供：
`execute_shell`、`ssh_exec`、`kill_process`、`delete_file`、`disable_service`、`change_firewall`、`upload_arbitrary_file`、`download_arbitrary_file`。

未来如建设处置能力，应独立服务、独立权限、审批和二次确认，不得复用扫描工具权限。

## 4. Skills 设计
Skill 负责流程指导：
1. 确认目标在授权清单。
2. 默认先 dry-run。
3. 解释范围、Profile 和影响。
4. deep / incident-response 先申请审批。
5. 调用 MCP 或 CLI。
6. 检查任务完整性。
7. 审阅规则发现项后再 AI 研判。
8. 报告区分事实、推断、未知和未覆盖。
9. 给整改建议，但不执行修复。

完整 Skill 文件位于 `.agents/skills/host-security-inspection/SKILL.md`。

## 5. 插件结构
```text
host-security-inspector-plugin/
├── .codex-plugin/plugin.json
├── .mcp.json
└── skills/
    └── host-security-inspection/SKILL.md
```
MCP URL 必须使用真实部署端点；模板中的占位地址不能直接上线。

## 6. Agent 调用流程
`list_authorized_hosts` → `plan_host_scan` → 审批（如需要）→ `run_host_scan` → `get_scan_status` → `list_findings` → `analyze_scan_findings` → `generate_scan_report`。

Agent 不得因用户说“全面检查”就扩大到未登记网段或其他主机。
