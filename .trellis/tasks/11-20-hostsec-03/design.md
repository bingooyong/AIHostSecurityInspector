# HOSTSEC-03 技术设计

状态：本任务交付PARTIAL；以下新增契约与测试为计划。当前有效目录和依赖方向遵循REPOSITORY-LAYOUT及ADR-008。

## 当前实现与迁移边界

03A已交付离线CLI、资产/固定Profile与计划；当前用户要求把原根Go工程迁入backend。本任务的“目录迁移”是其中一个可独立审查的切片，迁移完成不会自动满足版本元数据、干净重复构建、发布打包等剩余要求。源V1与bootstrap日志描述旧路径，原字节保留。

## module / 程序 / 共享内核

`backend/go.mod`声明`github.com/bingooyong/AIHostSecurityInspector/backend`；Go imports统一该前缀，所有运行入口在backend/cmd，跨入口共用backend/internal。当前只有hostsec；其他程序只在目录SDD中规划，不加空main。backend/tools放Go工程工具，root/scripts放跨工程Python脚本。根Makefile通过`go -C backend`或显式cwd调度，目标产物用repo/build绝对路径。

不引入go.work、根replace、GO111MODULE补丁、新框架或DI依赖。未来常驻hostsec-agent与AI Agent不是同一个模块，现阶段一次性Collector不因此变为常驻Agent。

## 构建输入与manifest

输入为固定工具链、backend/go.mod/go.sum、源码快照、目标GOOS/GOARCH、CGO_ENABLED、版本字符串和构建flags。沿用现有`backend/internal/cli.Version`作为版本注入点；注入路径必须跟随module/backend，version JSON暂不偷偷新增字段。提交OID、dirty/source-tree摘要、构建时间来源和flags放manifest，不把当前脏工作树伪称某个干净提交。

manifest至少为schema_version、binary_name、version、source_commit（可空但必须说明）、source_tree_hash、dirty、go_version、goos、goarch、cgo_enabled、build_flags、sha256、size_bytes、validation_level。禁止把包含绝对路径、用户名或凭据的环境整体写入manifest。若增加构建时间，明确固定SOURCE_DATE_EPOCH或允许其造成不可重复；重复性比较必须固定所有输入，不能比较本机不同架构binary。

发布模块tag未来采用backend/vX.Y.Z；本任务只在本地产出包、SBOM和摘要，不创建tag或远端release。扫描器、规则和数据库不随本切片安装。

## 隔离与错误

特权Collector上线前必须有独立binary依赖树门禁，禁止反向导入CLI/Analyzer/Provider/API/MCP/数据库；单module/internal并不提供进程权限隔离。构建命令失败、依赖校验失败、版本为空/非法、架构不支持、hash不符均返回非零并保留原日志；不得仍生成成功manifest。root与backend两种开发入口均须验证，不使用当前cwd猜仓库路径。

## 兼容、回滚与证据

只反向移动本任务列出的文件并恢复构建配置，按迁移前摘要对账；历史证据/V1源永不覆盖。版本/manifest格式变化保留旧兼容读取说明，不撤销其他任务业务修改。

完成证据：docs/05-testing/evidence/layout-migration为目录切片；完整03另存hostsec-03，包含两次构建输入/命令/退出/hash、版本正反例、SBOM、dirty声明和独立审查。 对应日志必须包含命令、工作目录、实际退出、输入/源码版本与验证范围；没有结果不写PASS。
