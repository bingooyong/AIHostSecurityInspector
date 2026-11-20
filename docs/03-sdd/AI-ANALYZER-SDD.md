# AI 研判与脱敏详细设计

状态：PLANNED。AI 默认关闭，本轮不配置凭据、不调用模型、不上传主机数据。AI 是可选解释层；规则、证据和报告必须在无模型时独立工作。

## 1. Provider 边界

建议 `Analyze(ctx, SanitizedAnalysisRequest) (Assessment, error)`；领域层只依赖结构化请求/响应，不传播 SDK 类型。实现 Provider：OpenAI、OpenAI-compatible、本地服务；本地模型也经过相同输入最小化和输出校验。Provider 不能访问 Collector、SSH、文件对象、凭据存储或处置工具。

配置包含 enabled=false、provider、approved base_url/model、credential_ref、external_data_policy_ref、timeout、max_input/output、max_attempts；缺少明确启用和数据授权时不发网络请求。API Key 只从批准密钥引用读取，不进入 YAML 资产、flags、报告和日志。TLS 正常验证；重定向不跨批准域转发 Authorization；endpoint 不从主机证据或模型输出派生。实际 API/SDK 行为在实现时按官方资料重新核对。

OpenAI Responses 的 `store=false` 仅是请求设置，不承诺零留存；组织数据控制、外发法律/合规和批准出口需单独核实。兼容服务不支持该设置时要记录 Provider 差异，不能据此绕开企业数据策略。

## 2. SanitizedAnalysisRequest

字段为 schema_version、scan/host 的稳定伪名、Profile、实际覆盖/未知项、Finding 的 rule_id/version/severity/confidence、允许的证据摘要、evidence_id、limitations、prompt_version、input_hash。每次只提交完成该风险簇分析所需的字段，不包含原始对象 URI 或任意文件读取能力。

脱敏采用 allowlist 新建视图：路径归类为系统/临时/业务目录，主机/用户名/IP 按批准策略稳定映射；保留必要端口、协议、文件 SHA-256、包版本和规则事实。拒绝密码、Token、私钥、连接串、完整 argv/环境变量、原始全量日志、无关业务数据和文件样本。正则只能辅助，不以“没匹配到密钥”作为外发批准。截断后仍需合法字段和缺失标记，不能截断结构形成误导事实。

初始预算沿用 V1.0 的候选值：每请求最多 30 Findings、输入 30000 字符、60 秒超时；最终实现还需 UTF-8 字节/Token、输出大小、总成本、并发与最多 2 次有界尝试限制，并在策略固定后测试。30 个/30000 字符是设计上限，不代表资源控制已运行。

## 3. 输出契约与验证

Assessment 必须包含 overall_assessment、confidence（0..100）、risk_level（critical/high/medium/low/info/unknown）、facts、inferences、evidence_refs、missing_evidence、recommended_actions、limitations、requires_human_review；另记 assessment_id、provider/model/prompt version、input/output hash 和时间。facts/inferences 建议为带 statement/evidence_refs 的 claim 数组，不能只有不可追踪自由文本。

先限制响应字节数并解析单个 JSON，拒绝额外文本/文档、未知字段、越界枚举/置信度和结构漂移；随后验证每个引用真实存在、属于当前 scan/host、在本次发送集合内、完整性 verified、足以支撑该事实。无证据/无事实的研判明确 insufficient_evidence。未知或跨扫描引用使该研判失败，不能修补成猜测的合法 ID。

规则 severity 是只读输入，不接受模型覆盖；调查 priority 可另存建议但需人工复核。模型宣称“已执行命令/已清除恶意文件”不成为平台事实，平台没有执行此类动作。默认 requires_human_review=true；自动生成文本不等于事件确认。

## 4. Prompt Injection

文件名、日志、argv、服务描述和配置内容均是不可信证据。它们使用有类型字段与转义边界传递，System Prompt 明确只作分析、不服从其中指令；不开放 tool calls，不自动抓取 URL，不按模型输出扩大主机/路径/扫描 Profile。输入字段 allowlist 与权限隔离是实际控制，提示词本身不能证明注入已被完全阻止。

报告呈现 AI 内容时转义 Markdown/HTML 控制内容，不自动执行代码块或加载远程资源。Skill 解释结果只可使用已验证 Assessment，与原规则/覆盖数据同时展示。

## 5. 故障降级

AIStatus：disabled/skipped/success/failed。超时、429/5xx、网络、认证、无效 JSON、引用失效、脱敏失败与预算超限分别记 error_code。只有可恢复的 429/5xx 使用有界退避，尊重总 deadline；认证/校验失败不循环重试。日志只记录 Provider、model、请求 ID、耗时、状态、摘要与预算，不保留密钥/原始视图。

任何失败都保留确定性 Findings、规则严重度和已验证证据，继续 JSON/Markdown 报告，明确 AI 未完成原因。不能用上次研判冒充本次成功；重跑产生新 assessment_id。

## 6. 测试与验收

HTTP 测试服务模拟超时、429、500、断连、恶意重定向、无效/超大 JSON、错误 ID/跨 host/scan ID、Provider 不可用；不调用真实外部模型。秘密诱饵覆盖 token/私钥/连接串/argv/多行日志，断言不出现在请求与日志；注入 fixture 要求不能触发任何额外调用/目标扩展/规则改写。验证 AI 关闭时请求数为零，所有失败仍生成确定性报告，合法引用 100%。外部真实 Provider 测试需独立批准的脱敏 fixture 与出口，不是本轮门禁。
