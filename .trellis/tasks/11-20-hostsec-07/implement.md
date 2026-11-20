# HOSTSEC-07 实施计划

日期2026-11-20；当前交付PARTIAL。下列10项是本任务内执行检查项，不是新增Trellis任务。目录迁移中的已做工作仍以本轮正式报告验收，不在计划中预勾选。

## 有序执行

- [ ] 1. 确认06 Snapshot和32A审批验收，读取04规范化intent/hash向量；明确07不反向成为32A实现前置。
- [ ] 2. 冻结policy/plan版本与字段单位，编写严格Schema和合法/恶意/越界fixture，不复用宽松原V1样例。
- [ ] 3. 实现受控module/tool注册表和四Profile继承/IR定向校验，禁止READ_ONLY或审批保护被策略关闭。
- [ ] 4. 实现资源/路径请求只能收紧的合并规则，完整展示未执行限额及风险/盲区。
- [ ] 5. 构建绑定资产/策略/主体/身份/范围/预算/有效期的intent和plan_hash，补每个安全字段变更测试。
- [ ] 6. 接入32A验证器，覆盖签名/窗口/撤销/过期/目标漂移；不接受任意非空approval-id。
- [ ] 7. 实现纯Preflight与受控capability/resource/clock测试输入，缺信息失败关闭，不在plan联网探测。
- [ ] 8. 与36约定启动时复核/审批消费以及运行守卫输出，写未实现运行部分，不加成功scan占位。
- [ ] 9. 跑四Profile、计划Schema、授权/TOCTOU/压力/窗口/取消矩阵与独立安全审查。
- [ ] 10. 保存policy/plan/approval样例hash和拒绝证据，更新CLI/Collector SDD；无真实守卫证据仍不能宣称扫描可执行。

## 验证入口

以下从仓库根执行；直接Go命令显式进入backend。新增模块测试、fixture或脚本尚不存在时先完成对应步骤，再运行命令；空包/匹配不到测试不能被当成功验收。

```sh
go -C backend test -race -count=1 ./...
go -C backend vet ./...
make lint
make build
python3 scripts/contracts.py
python3 scripts/integration.py
make check
```

具体名称和结果按实际实现登记，不伪造未来测试函数已存在。外部集成/运行环境不可用时记录BLOCKED及下一条可独立推进的工作；不得用跳过测试得到“全部通过”。

## 并行与完成

前置：HOSTSEC-06, HOSTSEC-32A。不同文件且无接口依赖时可并行；共享Schema/CLI/构建/状态修改串行。需求→设计→实现→自测→独立审查→验收全部有证据后才标IMPLEMENTED，不能仅因设计、编译或目录移动完成关闭本任务。

完成证据：docs/05-testing/evidence/hostsec-07：policy/intent/hash golden、四Profile及逐字段篡改矩阵、审批与Preflight拒绝、未实现守卫说明。

回滚：策略/计划格式版本化且保留只读导入，不覆盖已签审批/旧计划；新增策略失败不回退到更宽松默认，回滚不执行旧过期任务。
