# AI Host Security Inspector（企业主机智能安全巡检平台）

版本：V1.0｜日期：2026-11-20｜状态：方案基线，可进入需求确认与 MVP 开发。

## 文档目录
- `00-总体建设规划.md`：目标、路线和关键决策
- `01-需求规格说明书.md`：角色、功能、非功能需求和验收
- `02-技术架构设计.md`：分层架构、部署拓扑和技术栈
- `03-SDD-详细设计.md`：领域模型、状态机、接口和存储
- `04-巡检范围与检测规则.md`：Linux / Windows 检查范围和规则
- `05-CLI-MCP-Skills接口规范.md`：CLI、MCP、Skills 和插件
- `06-AI研判与数据治理.md`：模型接入、脱敏、Prompt Injection 防护
- `07-安全边界与应急响应.md`：只读边界、权限、威胁模型和应急流程
- `08-实施路线与验收测试.md`：实施阶段、测试和验收
- `09-部署与运维手册.md`：CLI、Runner、离线部署和运维
- `10-Codex-Claude执行任务书.md`：交给 Codex / Claude Code 的实施任务书
- `11-参考资料与选型依据.md`：官方资料与许可证审查
- `MVP-开发检查清单.md`：实施检查项
- `schemas/scan-result.schema.json`：扫描结果 Schema
- `examples/hosts.example.yaml`、`examples/policy.example.yaml`：配置示例
- `.agents/skills/host-security-inspection/SKILL.md`：可复用 Skill
- `plugin/`：插件包结构示例

## 核心决策
1. 专业工具负责检测，规则引擎负责确定性判断，AI 负责关联研判和报告。
2. CLI 是第一阶段入口，不是最终架构；CLI、MCP、Web 共用同一引擎。
3. 默认只读，不自动杀进程、删除文件、隔离主机或修改配置。
4. Agent 不获得任意 Shell；只允许调用经过授权的高层巡检动作。
5. 每条发现必须关联证据、采集时间、采集器版本、规则版本和 SHA-256。
6. 模型可替换：OpenAI API、兼容接口和本地模型统一接入。
7. 按网络安全域部署 Runner；隔离区采用出站拉取任务或离线结果包。
8. Linux 优先，支持架构设计预留 Windows；MVP 优先 Linux x86_64 / ARM64。

## 待确认
主机 OS / 版本 / 架构、数量、网络区域、堡垒机、SSH / sudo 策略、是否允许安装专业工具、模型 API 出网审批、日志留存要求。未知信息标记“待确认”，不得由 Agent 假设。

## MVP 范围
Go CLI、Linux 只读采集器、SSH 主机指纹校验、quick / standard / deep Profile、规则引擎、JSON / Markdown 报告、可选 osquery / Lynis / OpenSCAP / ClamAV / YARA、AI 脱敏研判、Codex Skill。

不在 MVP：自动处置、未授权网络探测、EDR 替代、多租户 SaaS、无审批生产深度扫描。
