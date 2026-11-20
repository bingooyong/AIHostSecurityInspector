# HOSTSEC-03 实施计划

日期2026-11-20；当前交付PARTIAL。下列8项是本任务内执行检查项，不是新增Trellis任务。目录迁移中的已做工作仍以本轮正式报告验收，不在计划中预勾选。

## 有序执行

- [ ] 1. 核对03A完成证据、现有工作区与V1/历史证据；冻结11条CLI行为和当前源码摘要，先跑既有race安全网。
- [ ] 2. 依ADR-008迁移Go module/cmd/internal/lint/Go工具到backend，同步imports和测试fixture路径，保持CLI行为。
- [ ] 3. 同步root Makefile、scripts cwd/源码hash/绝对产物路径与CI的backend go.mod/go.sum；加入目录边界与行为对比门禁。
- [ ] 4. 补齐默认dev与显式版本注入、非法版本拒绝，记录binary与manifest一致性；不在CLI v1静默新增字段。
- [ ] 5. 固定可复现构建输入，分别在两个空临时输出目录构建同一目标，比较hash并解释工具链/时间/dirty因素。
- [ ] 6. 产出本机CLI与Linux双架构binary、ELF/架构/hash清单、SBOM和源码/工具链元数据；校验错误负例。
- [ ] 7. 独立审查目录/依赖边界和构建脚本，不把Collector/Agent未来路径变成空功能；修复后重跑受影响门禁。
- [ ] 8. 更新部署文档、ADR/任务证据和状态，只有上述构建发布判据全部满足才关闭03；本轮迁移证据单独保存。

## 验证入口

以下从仓库根执行；直接Go命令显式进入backend。新增模块测试、fixture或脚本尚不存在时先完成对应步骤，再运行命令；空包/匹配不到测试不能被当成功验收。

```sh
go -C backend list -m
go -C backend test -race -count=1 ./...
go -C backend vet ./...
make lint
make build
python3 scripts/check_layout.py
python3 scripts/build_release.py
make check
```

具体名称和结果按实际实现登记，不伪造未来测试函数已存在。外部集成/运行环境不可用时记录BLOCKED及下一条可独立推进的工作；不得用跳过测试得到“全部通过”。

## 并行与完成

前置：HOSTSEC-03A。不同文件且无接口依赖时可并行；共享Schema/CLI/构建/状态修改串行。需求→设计→实现→自测→独立审查→验收全部有证据后才标IMPLEMENTED，不能仅因设计、编译或目录移动完成关闭本任务。

完成证据：docs/05-testing/evidence/layout-migration为目录切片；完整03另存hostsec-03，包含两次构建输入/命令/退出/hash、版本正反例、SBOM、dirty声明和独立审查。

回滚：只反向移动本任务列出的文件并恢复构建配置，按迁移前摘要对账；历史证据/V1源永不覆盖。版本/manifest格式变化保留旧兼容读取说明，不撤销其他任务业务修改。
