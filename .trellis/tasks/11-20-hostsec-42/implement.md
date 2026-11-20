# HOSTSEC-42 实施计划

日期2026-11-20；当前交付PARTIAL。下列9项是本任务内执行检查项，不是新增Trellis任务。目录迁移中的已做工作仍以本轮正式报告验收，不在计划中预勾选。

## 有序执行

- [ ] 1. 盘点已有门禁/工具版本/旧失败与产物，区分源码形状、CLI运行、未来契约、Linux真实运行及远端CI五类证据。
- [ ] 2. 改为backend module cwd和正确lint/config/cache路径，加入根目录Go回归门禁及root/backend双入口验证。
- [ ] 3. 规范GateResult与日志目录/退出/未执行状态，迁移证据独立保存并覆盖当前源码hash，不修改bootstrap原件。
- [ ] 4. 补真实CLI/Schema正反、DAG/来源/本地链接、现有AST安全检查，防只检查JSON语法或测试空实现。
- [ ] 5. 接入依赖校验/固定工具/可达漏洞与module告警台账、CycloneDX SBOM，测试缺工具/超时/数据库不可达故障分类。
- [ ] 6. 验证两架构ELF/hash/manifest、版本注入/可复现构建结果，确保读取的是本轮当前源码产物。
- [ ] 7. 为后续规则/Collector/证据/SSH/AI/前端建立明确启用表与缺环境BLOCKED规则，不创建fake pass job。
- [ ] 8. 独立审查CI权限/cache/外发日志与脚本cwd，修复后完整本地gate重跑；远端结果只在真正触发后登记。
- [ ] 9. 记录本地及可用远端run证据/未完成gate，更新TEST-STRATEGY/README/风险与任务状态，保留42当前PARTIAL直至其验收全达标。

## 验证入口

以下从仓库根执行；直接Go命令显式进入backend。新增模块测试、fixture或脚本尚不存在时先完成对应步骤，再运行命令；空包/匹配不到测试不能被当成功验收。

```sh
go -C backend mod verify
go -C backend test -race -count=1 ./...
go -C backend vet ./...
make lint
make build
python3 scripts/check_layout.py
make check
python3 scripts/build_release.py
```

具体名称和结果按实际实现登记，不伪造未来测试函数已存在。外部集成/运行环境不可用时记录BLOCKED及下一条可独立推进的工作；不得用跳过测试得到“全部通过”。

## 并行与完成

前置：HOSTSEC-03A。不同文件且无接口依赖时可并行；共享Schema/CLI/构建/状态修改串行。需求→设计→实现→自测→独立审查→验收全部有证据后才标IMPLEMENTED，不能仅因设计、编译或目录移动完成关闭本任务。

完成证据：docs/05-testing/evidence/hostsec-42：toolchain/命令cwd/退出、源码hash、各gate范围/未执行状态、SBOM/构建清单、失败分类负例及真实远端run URL（若未运行明确缺口）。

回滚：CI配置与脚本按作用域小步回滚，保留每轮原始日志/hash；不能删失败日志来修复指标，旧cache不当可信来源，远端权限始终最小。
