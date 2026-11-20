# 10. Codex / Claude Code 工程实施任务书

你是资深 Go 平台架构师、Linux 安全工程师、DFIR 工程师和测试负责人。请基于本目录 PRD、架构、SDD、规则和安全边界文档，在当前仓库实现 AI Host Security Inspector。

## 一、工作模式
- `MODE=INVENTORY`：只读盘点仓库和依赖。
- `MODE=DESIGN`：补齐设计和接口。
- `MODE=IMPLEMENT`：分任务实现。
- `MODE=TEST`：测试和构造 fixture。
- `MODE=REVIEW`：对抗式审计。
- `MODE=ACCEPTANCE`：基于真实证据验收。

## 二、硬性边界
1. 不连接生产主机。
2. 不扫描未授权 IP、网段或第三方系统。
3. 不执行真实恶意样本。
4. 不删除文件、不杀进程、不修改配置、不封禁网络。
5. 不把任意 Shell / SSH exec 暴露给 Agent。
6. 不打印或提交密钥、Token、密码和私钥。
7. 不将原始日志、环境变量和文件样本上传外部模型。
8. 主机采集测试使用本地 VM、容器或静态 fixture。
9. 未知要求标记待确认，不编造。
10. 编译通过不等于项目完成。

## 三、先做仓库盘点
检查 Go 版本、目录结构、CLI 框架、配置、日志、Agent / MCP、CI、测试、发布流程和可复用模块。输出 `docs/implementation/00-repository-inventory.md`，此阶段不改生产代码。

## 四、建议工程结构
```text
cmd/hostsec/
internal/
  asset/ authorization/ policy/ planner/ orchestrator/
  collector/linux/ collector/windows/
  transport/local/ transport/ssh/ transport/offline/
  tools/osquery/ tools/clamav/ tools/yara/
  tools/openscap/ tools/lynis/
  normalize/ rules/ evidence/ analyzer/ report/ audit/ storage/
pkg/schema/
rules/ policies/ examples/ testdata/
.agents/skills/host-security-inspection/
docs/
```
按现有仓库规范调整，但保持领域边界清晰。

## 五、任务顺序
1. CLI 骨架：version、doctor、assets validate、plan。
2. 领域模型和 JSON Schema。
3. hosts.yaml、policy.yaml、授权校验和审批。
4. Linux 只读 Collector：身份、进程、网络、账号、服务、持久化、安全配置、软件包。
5. SSH Transport：host key pinning、SSH Agent、ProxyJump、固定远端入口。
6. Evidence：原始 / 标准化分离、SHA-256、manifest、报告。
7. 规则引擎：YAML、正反例、Finding 证据关联。
8. 专业工具 Adapter：osquery、Lynis、OpenSCAP、ClamAV、YARA。
9. AI Analyzer：Provider 抽象、脱敏、结构化输出、证据 ID 校验。
10. Skill 和 MCP：只暴露高层巡检工具，不创建 exec_shell。
11. 对抗式审计：命令注入、路径穿越、SSH 绕过、sudo 过宽、证据篡改、Prompt Injection、凭据泄漏、资源耗尽、假绿。
12. 验收：测试、SBOM、构建摘要、部署文档、示例报告。

## 六、质量门禁
- gofmt、go vet、lint 通过。
- 核心模块有测试。
- 规则有正反例。
- JSON Schema 校验通过。
- 无硬编码凭据。
- 无关闭 SSH 指纹校验的配置。
- 无任意 Shell 执行入口。
- 无扫描自动处置行为。
- 模型输入完成脱敏。
- AI evidence_id 引用有效率 100%。
- 所有失败和部分成功状态有测试。

## 七、最终交付
可构建 CLI、Linux 只读 Collector、配置示例、规则库和 fixture、JSON Schema、报告样例、Codex Skill、MCP 工具定义、部署文档、测试报告和安全审计报告。

每个功能标记 `implemented / partial / planned / blocked` 并附证据。不得把“计划实现”写成“已完成”。
