# HOSTSEC-32A 技术设计

状态：本任务交付PLANNED；以下新增契约与测试为计划。当前有效目录和依赖方向遵循REPOSITORY-LAYOUT及ADR-008。

## 信任模型进入gate

先在实施前记录“谁能独立证明requester/approver、谁控制public-key trust store、谁持私钥、谁能修改执行机文件”的威胁模型。最低本地方案由管理员配置受保护trust store，将key_id映射到稳定审批principal、允许安全域/Profile和有效期；运行主体由受信任本机身份适配取得，不能接受CLI/JSON自报角色。签名记录中的approver必须匹配key绑定，requester必须匹配实际调用主体，二者不同只是必要条件，不是认证。

具体企业OS身份映射、审批密钥托管/轮换和受控目录所有权尚未提供，属于真实运行启用gate。可以用隔离测试密钥/固定可信principal完成验证器，但不能写“已实现企业审批隔离”。若同一OS用户能改trust store、审批私钥和replay日志，本地无法宣称抵御该用户伪造独立审批；必须披露并在生产部署前由独立审批服务/系统权限安排补齐。

## 签名与内容

依赖04的规范化ExecutionIntent版本/hash，32A不import planner/07。审批包至少为schema_version、approval_id、key_id、algorithm、intent_hash/canonicalization_version、requester_principal、approver_principal、host_ids/identity_refs/zone、profile、policy/asset hashes、resource/path scope hash、valid_from/until、maintenance_window、nonce、decision=approved、signature。安全内容全部进入签名；未知算法/字段/重复key/无界内容拒绝。

初始实现优先评估Go标准库Ed25519，固定算法/编码和domain-separation上下文后经设计审查冻结；不自己设计密码算法，不引入远程KMS依赖来证明接口。私钥不进资产/计划/证据/日志/flags，签名工具或审批服务的密钥管理另受控。本任务本地验证器不提供任意私钥导入/自动批准入口。

## 决策与消费

Verify(ctx,intent,approval,principal,trust,clock)为无副作用验证，返回VerifiedApproval（调用方不能自行构造为已验证）或安全错误；Check/Preflight不消费nonce。ConsumeAndAudit(ctx,verified,executionBinding)在实际启动前被36调用：持有跨进程互斥，复核有效期/撤销/执行绑定，原子记录nonce消费与允许事件、同步持久化成功后才授予单次启动许可。决定与消费分开防止dry-run耗尽审批。

审计最低字段为event_id、timestamp、request_id、actor_principal、action、approval/plan/host refs、decision、reason_code、nonce_digest、previous_hash与event_hash；不存密钥、签名私密材料或原始资产正文。链式hash只是篡改线索，不等于外部不可抵赖。所有拒绝尽力留痕，允许决定必须在审计持久成功后返回；写失败、锁失败、状态损坏拒绝启动。

## 32A早于SQLite的存储策略

15的完整SQLite证据库不是本任务DAG前置；不能为了32A偷偷引入生产数据库。首个实现切片需选定并测试受控本地append-only journal：独占安全目录、拒绝symlink、跨进程锁（不是仅Go mutex）、有界记录帧/校验、同一持久事件含nonce消费和audit决定、fsync后才返回许可。崩溃后的已消费审批保持已消费，宁可重新审批，不自动恢复未证明安全的“未消费”状态；截断/无法恢复journal失败关闭。平台/15数据库落地后用显式迁移/事务适配，不改变审批语义。

错误至少APPROVAL_REQUIRED/INVALID_SIGNATURE/UNKNOWN_SIGNER/IDENTITY_UNVERIFIED/SELF_APPROVAL/FORBIDDEN_SCOPE/EXPIRED/NOT_YET_VALID/REVOKED/REPLAY/PLAN_CHANGED/WINDOW_CLOSED/AUDIT_UNAVAILABLE/STATE_CORRUPT。错误只含稳定原因和已授权ID，不能泄露密钥或整个签名输入。

## 兼容、回滚与证据

审批格式/信任根版本化，rollback保留已消费nonce与审计历史；不恢复已失效/已消费审批。新旧journal迁移需对账，不删除日志“修复”验证错误。

完成证据：docs/05-testing/evidence/hostsec-32a：信任假设、签名字节/golden、全部拒绝矩阵、双进程至多一次许可、崩溃/锁/磁盘失败和审计持久记录；不得包含私钥。 对应日志必须包含命令、工作目录、实际退出、输入/源码版本与验证范围；没有结果不写PASS。

## 2026-11-25 PR7 防重放补强设计（当前切片）

复核确认 ledger.go 在 Open 时缓存、Consume 只持对象 mutex，并直接 WriteFile。可复现假设：两个提前打开的对象可消费相同 nonce，独立 nonce 写入丢失；写失败先污染 used。

沿 32A → 07 → 36 授权采集关键路径复用本任务，不新增 DAG 节点、不更改交付计数。替代方案：只加全局 mutex 无跨进程保障；迁入数据库超出当前兼容切片；采用现有 JSON 字符串数组 + 稳定 .lock 侧车 + 锁内重读 + 同目录随机临时文件 fsync/rename/目录 fsync。锁用非阻塞 flock，竞争失败关闭，避免无限等待阻碍取消。内存 ledger 保持现有行为。

安全边界：ledger/lock 为私有普通单链接文件，拒绝最终 symlink/FIFO/过宽权限、损坏/null/超过 1 MiB 状态。受信任操作者须提供私有本地目录及同一规范路径；不抵御可改父目录/删除 lock/回滚备份的本机所有者，不声称 NFS 分布式锁。缺失库仅初始化时允许；本对象一旦观察/提交持久状态，状态消失不能重建为空。成功只在同步后返回；rename 后同步错误可能已消费，保守拒绝，重试不得恢复 nonce。

仅修改 approval Ledger、其测试、相关 CLI 操作文档/质量规范和本任务记录。deep/IR、doctor/scan/mcp、loopback-only 契约完全不变。审计 journal 与独立 ledger 不宣称跨文件事务；原有 journal 是审计路径。
