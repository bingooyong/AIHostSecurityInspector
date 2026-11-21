# 证据与离线结果包详细设计

状态：PARTIAL。库级 EvidenceStore 已实现 Put/GetMetadata/OpenRaw/Recover（对象先落盘再登记元数据、0700/0600、孤立对象隔离不静默删除）；无签名/Manifest（HOSTSEC-16）、无导入导出、不能把 SHA-256 当来源真实或 verified。原始 V1.0 Schema 仅为草案，新契约必须按本设计和领域模型独立版本化。

## 1. 三个分离视图

RawEvidence 保存真实采集字节和采集失败事实；NormalizedEvidence 保存带 Schema 版本的结构化记录；AnalysisView 从已校验记录重新构造最小脱敏字段。三者具有独立 object_id、SHA-256、字节数、生成器版本与 lineage，AI 视图不能回写原始证据。默认不采无关业务内容、凭据、私钥、完整环境变量；必要授权日志本地受控保存。

Evidence 元数据至少包含 evidence_id、host_id、scan_id、attempt_id、collected_at/received_at、module、collector_name/version、category、source_type、raw_summary、raw_ref、normalized_ref、各对象摘要、collection_status、completeness、integrity_status、warnings；rule_version 记录在 RuleResult/Finding 与该证据的关联，不能在采集时伪称已经执行某版本规则。

## 2. 只追加写入协议

建议 `Put(ctx, EvidenceInput) -> EvidenceMetadata`、`GetMetadata(ctx, evidence_id)`、`OpenRaw(ctx, evidence_id)`、`Verify(ctx, scan_id) -> VerificationReport`、`Export/Import(ctx, BundleRequest)`。所有读取按 opaque ID，调用方不能指定任意磁盘路径。服务先验证 ID/host/scan 关系和配额，使用受控根目录、拒绝符号链接逃逸。

1. 在同文件系统受控临时目录以独占方式创建对象，目录 0700、文件 0600；边写边计算 SHA-256 与字节数，限制总大小。
2. 写入结束同步文件，原子放入不可覆盖的对象位置，再持久化元数据；既有 ID/对象不覆盖。
3. 元数据事务提交后加入 manifest；崩溃留下孤立对象可通过恢复扫描对账，不对未完成对象宣称 verified。
4. 标准化失败保留 raw 与失败状态；未采到任何原始内容时 raw_ref/hash 可缺失且 completeness=unavailable，不伪造摘要来满足 Schema。

只追加是应用约束，不代表持有本机管理员权限的攻击者无法更改文件；外部 WORM/签名和权限隔离需要独立部署能力。

## 3. Manifest

Manifest 含 schema_version、scan_id、host_ids、attempt_ids、created_at、producer/collector/policy/rule versions、对象条目（relative object path、size、SHA-256、media_type、evidence_id、view_type）、任务状态、覆盖摘要、签名元数据。签名针对规范化 manifest 字节，版本化规范化算法，拒绝重复路径/ID 与未知必需算法。

验证对所有对象重算摘要、核对大小与清单，检查无未声明替换对象、证据引用存在、同 host/scan、状态与对象一致。摘要失败为 integrity_status=failed，不能继续作为有效 Findings/AI 依据。哈希只证明对象相对清单未变；签名才绑定签名者，仍不能证明失陷主机内容真实性。

## 4. 离线包导入

首期格式按最终实现固定 tar.zst 及版本，不能仅因扩展名信任内容。导入先进入隔离暂存区；验证压缩总大小、解压总字节/文件数/比例、单文件上限、路径规范、重复条目、符号/硬链接、设备/FIFO、绝对路径、`..`、大小写冲突与覆盖，再验证 manifest/摘要/签名/ID 关系。全部成功后事务导入；失败不写正式历史库。未知签名者或未签名包明确 untrusted，不能自动成为远程执行或可信基线来源。

导出仅包含审批范围内的对象和脱敏报告；原始日志、个人信息、样本是否可导出由数据策略决定。导出行为记录 actor、scan_id、对象集合摘要、目标类别和时间，不记录凭据。

## 5. 发现项与 AI 引用

Finding 只能引用真实存在、同 host_id/scan_id、完整性有效并支撑该事实的 Evidence。缺失模块用 UNKNOWN/未覆盖报告；失败 evidence 可以证明“采集失败”本身，不能证明某账号/进程/端口安全。AI 引用进一步限制在本次发送的 evidence IDs；历史比较显式说明 baseline，不跨扫描偷换上下文。

## 6. 测试与验收

单元：空/二进制字节摘要、并发 ID 冲突、路径穿越、符号链接、写入失败、磁盘配额、取消与无摘要失败对象。集成：对象/manifest 各自篡改、删对象、重复 ID、签名过期/未知公钥、压缩炸弹/设备条目、崩溃中断与恢复、跨 host/scan 引用、整包往返。对象原字节与 hash、Finding 链接有效率 100% 是 MVP-4 门禁。没有完成这些测试，不把单纯 SHA-256 函数测试称为证据完整性验收。
