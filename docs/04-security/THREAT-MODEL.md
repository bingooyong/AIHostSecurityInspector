# 威胁模型

保护资产：授权范围、巡检凭据、主机可用性、原始证据、规则/策略供应链、审批签名密钥、AI外发与报告可信性。对手包括恶意主机内容、越权Agent/调用者、被篡改规则/包、失窃凭据和网络中间人。目标主机root可伪造采集视图；无可信硬件背书不能证明未被篡改。

| 边界/威胁 | 控制 | 验证与任务 |
|---|---|---|
| Agent→CLI参数命令注入 | 无exec表面、严格flags/目标枚举、固定argv | CLI注入/40工具执行器 |
| 主机输出→AI指令注入 | 数据隔离、无执行tool、schema/ref校验 | 26–29恶意文本 |
| 网络→SSH MITM | 固定known_hosts/host identity | 14 mismatch/轮换失败 |
| 用户→特权Collector | root-owned固定入口、最小sudo | 14安装权限/sudo审计 |
| 用户/Agent→未授权目标 | 全组原子校验、执行前复核、RBAC | 06/07/45越权/撤权 |
| 本地原文→Provider泄密 | 默认关闭、最小字段脱敏、出口allowlist | 26 canary/25重定向 |
| 假包→伪造结果 | 来源签名/nonce/manifest与导入事务 | 31/41伪签/重放 |
| 修改证据→报告失真 | raw/normalized双hash、同scan-host引用 | 16/18篡改回归 |
| 缺权限/超时→假PASS | collection状态和RuleResult四态分离 | 17/36故障矩阵 |
| 巨大输入/压缩→资源耗尽 | 字节/深度/别名/时间/文件与IO界限 | CLI/37/40/41压力 |
| 路径→目录穿越/挂载逃逸 | ID解析、safe open/拒绝symlink、受控根 | 15/37/41负例 |
| 第三方规则→执行/供应链 | 版本/来源/hash签名、有限DSL、正反例 | 17/24/42恶意包 |
| 误报→未经批准处置 | 无处置接口、人工复核 | 全表面检查/AC12–13 |

13类风险逐项落实于 docs/security/ADVERSARIAL-REVIEW.md。测试未覆盖的控制标PLANNED；不能把威胁表当防护完成证据。
