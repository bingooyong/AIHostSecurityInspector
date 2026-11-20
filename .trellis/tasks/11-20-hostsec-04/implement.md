# HOSTSEC-04 实施计划

日期2026-11-20；当前交付PARTIAL。下列9项是本任务内执行检查项，不是新增Trellis任务。目录迁移中的已做工作仍以本轮正式报告验收，不在计划中预勾选。

## 有序执行

- [ ] 1. 清点当前Go DTO、Schema与SDD字段/枚举差异，形成单一字段对照；先修正none/unavailable、timeout/skipped等不一致。
- [ ] 2. 冻结ID/UTC时间/版本/纯数据依赖约束及输入v1兼容策略，补每字段的必填/可空/范围测试数据。
- [ ] 3. 定义可签名ExecutionIntent与规范化/摘要v1及golden测试，明确哪些排序/字段变化必须改变hash。
- [ ] 4. 实现Host/Plan转换与ScanJob/Attempt状态纯函数，保持03A输出不变。
- [ ] 5. 实现Evidence/RuleResult/Finding/Assessment值验证与同scan-host关系验证，区分形状合法和内容引用合法。
- [ ] 6. 同步结果Schema与合法/非法JSON fixtures；新增schema版本兼容说明而不伪造运行证据。
- [ ] 7. 添加终态/时间倒置/空引用/失败证据/跨主机/重复ID/无基线/未知版本等矩阵测试。
- [ ] 8. 跑纯Go依赖树检查、race/vet/lint、真实CLI与Schema集成；独立检查模型重复与JSON tag漂移。
- [ ] 9. 记录关系/摘要golden和命令退出证据，更新DOMAIN/EVIDENCE/CLI SDD，只有完整模型与语义验证达标才关闭04。

## 验证入口

以下从仓库根执行；直接Go命令显式进入backend。新增模块测试、fixture或脚本尚不存在时先完成对应步骤，再运行命令；空包/匹配不到测试不能被当成功验收。

```sh
go -C backend test -race -count=1 ./...
go -C backend vet ./...
make lint
python3 scripts/contracts.py
python3 scripts/integration.py
make check
```

具体名称和结果按实际实现登记，不伪造未来测试函数已存在。外部集成/运行环境不可用时记录BLOCKED及下一条可独立推进的工作；不得用跳过测试得到“全部通过”。

## 并行与完成

前置：HOSTSEC-03A。不同文件且无接口依赖时可并行；共享Schema/CLI/构建/状态修改串行。需求→设计→实现→自测→独立审查→验收全部有证据后才标IMPLEMENTED，不能仅因设计、编译或目录移动完成关闭本任务。

完成证据：docs/05-testing/evidence/hostsec-04：字段/枚举对照、合法及负例fixture、摘要golden、同scope关系失败记录、依赖树、CLI兼容结果。

回滚：实体和Schema分小步变更，保留当前v1 DTO及fixture；通过显式转换兼容旧版本，禁止覆盖已导出证据，回滚不删除历史结果。
