# MVP 开发检查清单

- [ ] 完成主机资产盘点，确认 Linux / Windows / 架构 / 网络区
- [ ] 明确巡检账号、堡垒机和 sudo 最小权限方案
- [ ] 确认生产扫描维护窗口和数据外发审批
- [ ] 建立 Go CLI 骨架与统一 Schema
- [ ] 实现资产校验、dry-run、授权控制
- [ ] 实现 Linux 只读 Collector
- [ ] 实现 SSH host key pinning
- [ ] 实现 Evidence SHA-256 和 manifest
- [ ] 实现规则引擎与正反例
- [ ] 实现 JSON / Markdown 报告
- [ ] 接入 osquery（可选但优先）
- [ ] 接入 Lynis / OpenSCAP
- [ ] 接入 ClamAV / YARA（先测试环境）
- [ ] 实现脱敏与 AI Analyzer
- [ ] 实现 Codex Skill
- [ ] 完成对抗式安全审计
- [ ] 在 3～5 台测试主机完成试点
- [ ] 评估后再进入 UAT / PROD
