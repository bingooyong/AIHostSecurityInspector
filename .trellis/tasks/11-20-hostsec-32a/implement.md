# HOSTSEC-32A 实施计划

日期2026-11-20；当前交付PLANNED。下列10项是本任务内执行检查项，不是新增Trellis任务。目录迁移中的已做工作仍以本轮正式报告验收，不在计划中预勾选。

## 有序执行

- [ ] 1. 核对04规范化intent/hash和06资产快照完成证据，冻结输入及可信principal接口，明确不依赖07实现。
- [ ] 2. 形成并审查本地身份/信任根/密钥托管/目录所有权威胁模型；真实企业未知列启用阻塞，不用自报字符串代替认证。
- [ ] 3. 冻结approval Schema、算法/签名字节/domain separation与严格解析界限，生成无害测试密钥和正反例。
- [ ] 4. 实现纯Verify及VerifiedApproval受控构造，覆盖签名者映射、操作审批分离和目标/策略/资源绑定。
- [ ] 5. 实现clock/维护窗口/撤销检查，覆盖精确到期、未来、无效时区、撤销后的旧计划。
- [ ] 6. 选择并实现受控journal/跨进程锁与ConsumeAndAudit，nonce消费和允许审计同一持久事件，失败关闭。
- [ ] 7. 补两进程竞争、崩溃/截断/磁盘满/目录权限/symlink/锁超时测试，不在非隔离真实目录试验。
- [ ] 8. 与07/36约定Preflight不消费、真实启动才消费的用法；计划验证成功不等于运行授权已执行。
- [ ] 9. 独立对抗审查身份假设/重放/日志伪造，跑全域race/vet/lint及无任意执行门禁。
- [ ] 10. 保存签名与并发恢复证据、更新审批/审计契约和部署进入gate；未满足真实身份托管条件时禁止启用deep/IR运行。

## 验证入口

以下从仓库根执行；直接Go命令显式进入backend。新增模块测试、fixture或脚本尚不存在时先完成对应步骤，再运行命令；空包/匹配不到测试不能被当成功验收。

```sh
go -C backend test -race -count=1 ./...
go -C backend vet ./...
make lint
python3 scripts/contracts.py
make check
```

具体名称和结果按实际实现登记，不伪造未来测试函数已存在。外部集成/运行环境不可用时记录BLOCKED及下一条可独立推进的工作；不得用跳过测试得到“全部通过”。

## 并行与完成

前置：HOSTSEC-04, HOSTSEC-06。不同文件且无接口依赖时可并行；共享Schema/CLI/构建/状态修改串行。需求→设计→实现→自测→独立审查→验收全部有证据后才标IMPLEMENTED，不能仅因设计、编译或目录移动完成关闭本任务。

完成证据：docs/05-testing/evidence/hostsec-32a：信任假设、签名字节/golden、全部拒绝矩阵、双进程至多一次许可、崩溃/锁/磁盘失败和审计持久记录；不得包含私钥。

回滚：审批格式/信任根版本化，rollback保留已消费nonce与审计历史；不恢复已失效/已消费审批。新旧journal迁移需对账，不删除日志“修复”验证错误。

## 2026-11-25 PR7 切片执行计划

- [x] RED：ledger_test.go 添加预先打开实例同 nonce 拒绝、不同 nonce 不丢失、写失败后重试、状态消失/损坏与文件类型拒绝、双进程竞争。运行 `go -C backend test -count=1 ./internal/approval -run TestLedger`，确认行为断言失败。
- [x] GREEN：ledger.go 保持 OpenLedger/Consume API，持侧车锁重读当前 JSON，检查 nonce 后用同目录随机临时文件同步原子替换，同步目录后返回；失败不提前更新内存。
- [x] 回归：approval/orchestrator/planner/audit race；make check 使用全新证据目录，默认 fixtures-only。
- [x] 审查：检查稳定锁跨 rename、旧格式兼容、失败关闭、nonce 保留、无秘密/原始主机数据；补操作说明与质量规范。
- [x] 本地验收：冻结 CLI 契约与非 loopback 拒绝，记录真实 36/11/1；23/23 PASS，证据见 docs/05-testing/evidence/hostsec-wp6-2026-11-25-ledger-hardening/REVIEW.md。
- [ ] 交付：提交同 PR7 分支，推送后 CI 仅查一次，不合并。

回滚仅还原代码，不回滚/删除已消费 ledger 和 .lock。未完成真实双架构 VM/平台身份/内网采集不宣称交付。
