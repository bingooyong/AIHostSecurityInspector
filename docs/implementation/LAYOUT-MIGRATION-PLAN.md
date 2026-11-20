# 工程目录迁移计划与行为锁定

范围：用户纠正根目录Go工程，已有主控任务内细化HOSTSEC-03的目录迁移切片，同时同步WP1近期实施文档；无需新增任务改变48节点数量。

行为差距：代码和工具默认根目录Go module，目标是backend内独立Go工程及仓库级多工程调度。行为落点：go.mod与imports、Go测试fixture、root Makefile、scripts中cwd/源码/哈希枚举、CI的toolchain和cache、Trellis包/任务路径。规则、Collector、AI、前端功能仍未实现，本次不扩大为业务开发。

执行与所有权：
1. 主会话：检查工作区/已有子进程，写本计划/目录SDD/ADR；跑既有race，冻结11条CLI基线和源码摘要。
2. Trellis implement：独占Go源码迁移（backend/cmd、internal、tools，go.mod/go.sum/.golangci）、fixture/import、root Makefile/.github/scripts，保持业务行为，补目录回归门禁。scripts/validate_baseline的文档语义由主会话同步；对接后再检查。
3. 主会话：同步当前docs/spec/Trellis package和DAG交付路径，WP1逐任务细化；历史源与bootstrap证据原字节保留。根不要创建空前端/Agent产品工程。
4. 迁移完成后Trellis check独立复核，机械问题可修，契约/安全问题报告；正式门禁在新evidence/layout-migration，读退出结果和产物摘要。
5. 同步状态/验证报告，保留项目整体PARTIAL和未来PLANNED；本轮无需发布、部署或Git提交。

回归条件：已存在的资产/四Profile/越权/注入/null/非普通文件测试就是行为安全网，迁移前通过后才能移动。11条真实CLI前后stdout/stderr/exit一致，schemas保持不变；未知命令仍非零、doctor不假报Collector可用。目录门禁防根Go工程回归；root与backend两种开发入口均验证。已有覆盖足够，本次不写镜像实现单测。

回滚：保留迁移前source hashes与CLI baseline；只反向移动已列Go文件/路径和构建适配，不覆盖用户已有未跟踪文件；不使用git reset/clean，旧证据与V1源始终不改。
