# 主控实施计划

1. IMPLEMENTED：读取来源、盘点环境、建立来源manifest。
2. 补齐需求/SDD/ADR/安全/测试与DAG，验证无环、路径和状态。
3. 审查首切片设计后 start HOSTSEC-03A，Trellis implement独立实现，check独立复核。
4. 执行本地测试/Schema/安全/漏洞/SBOM/双架构构建，记录真实日志和限制。
5. 更新状态、风险、README和执行报告；不把MVP整体标完成，不执行生产扫描。

## 当前执行切片：多工程目录
依LAYOUT-MIGRATION-PLAN先锁定行为，再迁移backend工程与构建/CI、同步文档/DAG/spec，独立check及验证，细化WP1近期任务；保持总48节点与业务实现状态真实。

本轮用户追加：系统更新AGENTS.md作为工程治理入口，保留Trellis托管块字节；规范位置为.trellis/spec/backend/go，实际配置backend包/go层，目录与AGENTS/spec加入验证。

本轮收尾：目录迁移/AGENTS/spec更新和WP1细化已完成，16门禁PASS+独立审查；见REPOSITORY-LAYOUT-REPORT。03/42完整任务仍PARTIAL，后续04为下一切片。
