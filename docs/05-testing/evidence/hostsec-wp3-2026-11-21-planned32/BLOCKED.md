# 外部阻塞（本轮不宣称完成）

- HOSTSEC-30 MCP：缺少已批准的 MCP 服务协议落地、调用者企业身份与权限过滤运行时。禁止创建空 `cmd/hostsec-mcp`。
- HOSTSEC-31 区域 Runner：缺少区域执行节点、独立部署身份与传递依赖门禁环境。
- HOSTSEC-32 平台审批：本地 32A 不能替代平台审批服务、密钥托管与企业身份。
- HOSTSEC-33/34/35 Web：未授权创建空 npm/Web 工程；无企业会话与 RBAC。
- HOSTSEC-45 RBAC：依赖平台身份。
- HOSTSEC-43 总体验收：无真实 VM/企业主机/生产部署授权；交叉编译不是运行验收。
- 远端 GitHub Actions：历史付款失败/spending limit；本地门禁通过 ≠ 远端 PASS。
- HOSTSEC-14 完整 SSH：安全边界门禁禁止 `golang.org/x/crypto/ssh` 与 `net`；无隔离 SSH 测试容器。仅落地 known_hosts 策略校验。
