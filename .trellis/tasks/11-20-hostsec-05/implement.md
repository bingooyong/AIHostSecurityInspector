# HOSTSEC-05 实施计划

日期2026-11-20；当前交付PARTIAL。下列8项是本任务内执行检查项，不是新增Trellis任务。目录迁移中的已做工作仍以本轮正式报告验收，不在计划中预勾选。

## 有序执行

- [ ] 1. 对照当前CLI每命令flags/help/stdout/stderr/exit，冻结兼容矩阵与未实现命令拒绝行为。
- [ ] 2. 把错误码和输出编码边界集中为小职责代码，保留业务错误映射且禁止敏感原文回显。
- [ ] 3. 明确timeout/concurrency强类型参数的适用命令、合法范围、context传播与资源说明；不接受无效但被忽略的flag。
- [ ] 4. 补writer失败、JSON编码失败、ctx预取消与处理时取消/超时单测，确认无结果假成功。
- [ ] 5. 添加可控慢用例测试辅助子进程，验证SIGINT/SIGTERM、deadline和有界退出，不连接主机。
- [ ] 6. 更新真实CLI进程Schema/参数注入/错误矩阵，保留doctor非就绪与未来命令非零。
- [ ] 7. 核对15/36未来status/retry接入协议，写明当前未实现和集成门禁，不用空scan_id结束任务。
- [ ] 8. 独立审计后记录命令结果/取消延迟/Schema证据并更新CLI-SDD；运行生命周期缺证据则保持PARTIAL。

## 验证入口

以下从仓库根执行；直接Go命令显式进入backend。新增模块测试、fixture或脚本尚不存在时先完成对应步骤，再运行命令；空包/匹配不到测试不能被当成功验收。

```sh
go -C backend test -race -count=1 ./...
go -C backend vet ./...
make lint
make build
python3 scripts/integration.py
make check
```

具体名称和结果按实际实现登记，不伪造未来测试函数已存在。外部集成/运行环境不可用时记录BLOCKED及下一条可独立推进的工作；不得用跳过测试得到“全部通过”。

## 并行与完成

前置：HOSTSEC-03, HOSTSEC-04。不同文件且无接口依赖时可并行；共享Schema/CLI/构建/状态修改串行。需求→设计→实现→自测→独立审查→验收全部有证据后才标IMPLEMENTED，不能仅因设计、编译或目录移动完成关闭本任务。

完成证据：docs/05-testing/evidence/hostsec-05：逐命令契约表、signal/timeout进程日志和退出码、writer故障、注入与敏感值canary结果。

回滚：命令适配与业务变更分别提交/审查；保留既有命令输出和error codes；未接通用例的命令从help撤除而非成功降级。
