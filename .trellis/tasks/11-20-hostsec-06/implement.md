# HOSTSEC-06 实施计划

日期2026-11-20；当前交付PARTIAL。下列8项是本任务内执行检查项，不是新增Trellis任务。目录迁移中的已做工作仍以本轮正式报告验收，不在计划中预勾选。

## 有序执行

- [ ] 1. 核对05/04合同与当前asset解析/授权负例，列输入v1兼容矩阵，决定新字段是否独立版本。
- [ ] 2. 实现规范化不可变Snapshot及content_hash，覆盖所有授权/连接相关字段，补顺序稳定和变更敏感测试。
- [ ] 3. 抽取严格目标选择/全组原子授权用例，保留registered ID/group限制与每Profile allowlist。
- [ ] 4. 实现按host_id的资产/组差异与安全字段摘要输出，不解析认证引用中的秘密。
- [ ] 5. 实现计划快照与执行当前快照的重验证，覆盖撤权/Profile/地址/区域/known_hosts变动。
- [ ] 6. 建立真实身份引用/未知/不一致的比较契约，08/14集成前只用无害fixture且不标实际身份验证完成。
- [ ] 7. 补文件替换/权限不足/取消/超限/恶意字段/全未授权列表往返测试，跑现有CLI Schema兼容。
- [ ] 8. 独立审查快照可变性与TOCTOU边界，记录差异/授权回归证据；真实transport复核未运行部分明确留后续集成gate。

## 验证入口

以下从仓库根执行；直接Go命令显式进入backend。新增模块测试、fixture或脚本尚不存在时先完成对应步骤，再运行命令；空包/匹配不到测试不能被当成功验收。

```sh
go -C backend test -race -count=1 ./...
go -C backend vet ./...
make lint
make build
python3 scripts/integration.py
python3 scripts/contracts.py
make check
```

具体名称和结果按实际实现登记，不伪造未来测试函数已存在。外部集成/运行环境不可用时记录BLOCKED及下一条可独立推进的工作；不得用跳过测试得到“全部通过”。

## 并行与完成

前置：HOSTSEC-05。不同文件且无接口依赖时可并行；共享Schema/CLI/构建/状态修改串行。需求→设计→实现→自测→独立审查→验收全部有证据后才标IMPLEMENTED，不能仅因设计、编译或目录移动完成关闭本任务。

完成证据：docs/05-testing/evidence/hostsec-06：Snapshot摘要golden、逐字段变动矩阵、混合组/撤权拒绝、diff fixture、文件与identity未知负例及CLI兼容。

回滚：快照/差异新增API与现有解析分离，保留v1输入及golden；不写回资产文件、不自动撤销主机或改密钥。回滚索引/适配不覆盖来源文件或旧计划记录。
