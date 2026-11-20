# YAML 规则引擎详细设计

状态：PLANNED。本轮没有规则运行或正反例通过证据；以下九条是首期最低实现要求。规则以确定性标准化证据为输入，AI 研判在其后且不能更改原始严重度。

## 1. 规则包契约

规则最低字段：rule_id、version、title、category、platform、profiles、severity、confidence、required_evidence、detection_logic、false_positive_notes、remediation_guidance、references。规则包另含 bundle_id/version、规则清单、各文件 SHA-256、来源、审查记录与签名状态。采用单一规范字段，V1.0 示例 `id/logic/evidence_required` 如需导入须显式迁移，不混用别名静默接受。

detection_logic 只允许代码登记的谓词，如 equals、in_set、path_under、is_deleted_executable、baseline_diff；字段路径与类型来自固定证据 Schema。禁止 eval、Shell、Go plugin、动态 SQL、正则无预算匹配或远程引用。YAML 严格字段/唯一键/单文档、大小/深度/规则数有界，加载失败整体拒绝该包，不跳过坏规则制造“全部通过”。

## 2. 四值求值

`Evaluate(ctx, EvidenceSnapshot, TrustedBaseline, RuleBundle) -> []RuleResult, []Finding` 为建议服务契约。先检查平台/适用性，再检查采集状态、字段完整性、摘要与同 host/scan 关联，再求值。明确不适用返回 NOT_APPLICABLE；缺字段/权限/工具/基线、摘要失败、超时或数据竞争返回 UNKNOWN，包含 missing_evidence/reason_code；条件命中返回 FAIL，不命中且必需范围完整才 PASS。

每条 RuleResult 固定 rule_id/version、证据 ID、baseline_ref、outcome 和解释。只有有足够真实证据的 FAIL 才生成风险 Finding；缺证据通过 UNKNOWN 与覆盖缺口报告，不生成无支撑的“木马/配置风险”。部分采集可以支持某个明确存在的异常，但不能据缺失条目证明“没有异常”。

## 3. MVP 九条规则与正反例

| ID | 检测逻辑与前置证据 | 正例（FAIL） | 反例（PASS）/边界 |
|---|---|---|---|
| PROC-001 | 非内核线程进程仍存在且 exe 目标已删除；记录 starttime 防 PID 复用 | 稳定 PID 与 deleted exe 证据 | 真实 exe 存在；EACCES/进程已退出为 UNKNOWN |
| PROC-002 | 可执行路径实际位于批准的可疑目录集合 | `/tmp/demo-agent` 执行记录 | `/usr/bin/demo`；只匹配目录边界，`/tmpx` 不命中 |
| NET-001 | 监听 protocol/address/port 与可信角色允许表比较 | 未登记 TCP 端口并有 socket 证据 | 登记端口；无允许表 UNKNOWN，PID 关联缺失单列 |
| IAM-001 | UID 0 或受控管理员组成员不在批准账号基线 | 新 UID 0 账号 | 批准 root/管理员；账号/基线不完整 UNKNOWN |
| PERS-001 | unit 新增/不在批准服务基线或可执行文件所有者/权限不安全 | 未批准 unit，或 unit/exec 可被非授权用户写 | 已批准且权限正常；非 systemd N/A，无基线 UNKNOWN |
| PERS-002 | cron/at 条目与批准任务基线比较，检查目标/归属 | 新增未批准 cron | 已批准任务；注释/空白规范化不当变更，文件不可读 UNKNOWN |
| IAM-003 | SSH 公钥指纹集合对可信前次基线变化 | 新增/移除指纹 | 相同指纹；不保存私钥；首次无基线 UNKNOWN |
| MAL-005 | 白名单扫描范围 SUID/SGID 文件与可信允许集比较 | 未登记 SUID/SGID 文件 | 登记文件/普通文件；范围截断不得证明全盘 PASS |
| CFG-001 | 指定关键配置原始字节/规范化摘要与可信版本比较 | 已批准对象范围内 SHA-256 变化 | 摘要相同；无基线 UNKNOWN，合法变更仍需复核 |

每条必须独立提供正例、反例、缺字段、部分采集、不适用和跨 host/scan 引用测试。变化规则要带明确 baseline_scan_id、可信基线版本和批准状态；首次扫描只能建立待批准候选基线，不能宣称“变化已检测通过”。误报说明包括合法软件升级、维护任务、动态端口和配置变更，规则输出仍等待人工核查。

## 4. 扩展规则

异常外联、父子进程、内核模块、文件权限、安全配置、恶意特征、漏洞版本和日志审计按对应证据落地。版本比较使用发行版 epoch/release/backport 语义，不能简单词典比较或仅凭上游版本报 CVE；离线情报缺失/过期或发行版无法匹配为 UNKNOWN。ClamAV/YARA 未执行不能输出“未发现病毒”。审计关闭/日志清理属于证据支撑的异常线索，不推断不存在日志即恶意清除。

## 5. 安全、预算与发布

规则只能读快照，不获得 Collector/文件写入/网络/处置接口。编排器按规则数、总求值时限、每规则预算和最大输出限制；超限产生 UNKNOWN 并保留先前结果，不删除未知项。规则包按来源和摘要固定，离线更新需审查、正反例、签名、灰度与回滚；不能在扫描时从 URL 拉取。严重度变更需规则版本升级，AI 建议 priority 单独保存。

`rules validate` 校验包/Schema/引用和有限谓词；`rules test` 执行每条 fixture 并要求匹配预期四值。九条未全部验收前 MVP-3 为 PARTIAL/PLANNED。报告必须显示执行规则数、FAIL/PASS/UNKNOWN/N/A、包版本、误报说明与未覆盖类别。
