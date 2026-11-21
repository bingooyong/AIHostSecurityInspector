# 存储、历史与恢复详细设计

状态：PARTIAL。库级切片 `backend/internal/storage` 与 `backend/internal/evidence/store.go` 使用 modernc.org/sqlite（CGO-free）做隔离临时库、版本化迁移、只追加对象和崩溃隔离；未接入 CLI/scan，integrity_status 默认 unverified，不表示扫描历史或平台存储已上线。

## 1. 分工与接口

SQLite 保存索引、关系、任务/attempt、审批、规则/策略快照、证据元数据、Findings、研判和审计；大对象由受控文件 EvidenceStore 保存。领域服务依赖按用例的窄接口，如 AssetRepository、ScanRepository、EvidenceRepository、FindingRepository，不用接受任意 SQL 或通用 map 的“大仓储”。

建议逻辑表：hosts/host_labels、scan_jobs、scan_attempts、module_results、approvals、evidence、evidence_objects、rule_results、findings、finding_evidence、rule_bundles、policy_snapshots、ai_assessments、audit_events。实施时逐任务迁移，不一次建空表证明完整。所有主机/扫描归属关系具有外键/唯一约束，应用层再查权限。

## 2. SQLite 约束

优先评估纯 Go 驱动以便 Linux 双架构离线构建；固定驱动与其要求的 libc 依赖版本后运行兼容测试，不先引入依赖。启用 foreign_keys，事务写入任务状态与元数据；有界 busy timeout、单写者策略、取消传播与明确磁盘满错误。是否 WAL、同步级别和 checkpoint 策略由崩溃恢复/资源测试确定，不为性能牺牲未确认的证据持久性。

SQL 全部绑定参数，动态排序/表名只能枚举白名单。schema_migrations 记录版本与摘要；升级前备份/校验，失败回滚，不能自动升级未知/外部生产数据库。数据库及证据根目录仅执行用户访问；不存在默认生产连接字符串。

## 3. 文件对象与事务边界

文件系统和 SQLite 无跨资源原子事务。EvidenceStore 先独占写临时对象并同步/原子固化，再事务登记元数据；崩溃后恢复器按对象/数据库/manifest 对账，孤立对象隔离或待修复，不静默删除调查证据。数据库引用尚未固化对象时 integrity_status=unverified，报告不能当 verified 使用。

对象不可覆盖；attempt 重试生成新对象与 ID。导入包全部验证后才提交索引，事务失败不保留半份正式结果；残留暂存区以受控清理流程处理。输出路径来自服务端对象 ID，禁止把 scan_id/evidence_id 当任意文件路径。

## 4. 查询与历史

assets list/status/findings/evidence/report 均按主体权限、host_id/scan_id 归属查询并分页有界。首期单用户本地 CLI 信任数据库所有者；平台阶段必须服务端 RBAC/区域过滤，不能复用本地文件可写模型作为租户安全边界。

历史差异基于明确选定的可信基线、host 身份、collector/规则版本与采集覆盖；不完整新扫描不能证明旧异常消失。first_seen/last_seen 由观察证据驱动，missing/unknown 与 fixed 分离。人工 confirmed/false_positive/accepted_risk/fixed/reopened 作为审计事件，不覆盖原始检测结果。

## 5. 恢复、备份与留存

进程启动发现 RUNNING 的旧 attempt，标记 interrupted 并保留证据；重试须重新授权/检查审批、使用新 attempt，不盲目继续过期任务。断点记录已固化模块和策略/输入摘要，配置变化不复用旧成功状态。

备份数据库与 manifest/object 集合使用一致快照，恢复后全量/策略化摘要与引用验证。密钥不随普通业务备份明文保存。留存周期、加密要求和法律保全待企业治理确定；没有策略不自动删除证据。证据删除是独立治理动作，不属于主机处置或扫描命令。

## 6. 平台迁移与验收

PostgreSQL 保存平台关系，MinIO/S3 保存对象，保留 ID/摘要/Schema 与领域接口。迁移须做行数、对象摘要、引用、历史和权限对账，不把 SQLite 文件直接暴露为远程数据库 API。

门禁包含迁移升级/回滚、并发扫描、写冲突、取消、磁盘满、断电/进程终止、对象与索引不一致、恢复重试、分页/越权查询、备份恢复和双架构实跑。仅数据库连通或建表成功不代表历史/证据可靠性实现。
