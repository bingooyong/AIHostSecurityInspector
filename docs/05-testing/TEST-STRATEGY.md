# 测试策略与CI门禁

## 分层验证

单元：资产/目标授权、四Profile、状态机、有限DSL、hash/manifest、引用、脱敏、AI输出。集成：真实CLI进程与Schema、临时SQLite、无害本地HTTP Provider、一次性SSH服务/测试VM、tar/zstd受限导入。Collector：Linux x86_64/ARM64测试VM，对照人工状态；fixture不能取代OS运行。权限不足/工具缺失/超时/被取消必须覆盖不足。规则：九条每条正/反/缺证据/无基线/适用性；漏洞按发行版版本语义和backport。安全：13项对抗矩阵、越权、注入、秘密canary、篡改/重放/路径逃逸、无处置。

资源：quick/standard/deep分别测wall time、CPU、peak RSS、读字节/IO、文件数/大小、取消延迟，先确定授权测试主机规格与基准预算；无实测不写低开销。deep压测只在隔离无害fixture且守卫开启。首次建议目标预算：CLI1MiB资产/1000主机解析≤2s/128MiB，需实测再固化；Collector预算必须与企业硬件共同验收。

## CI

每PR：gofmt、go vet、golangci-lint、go test -race、CLI集成、JSON Schema正反例、DAG/来源/链接校验、Go AST安全边界、govulncheck、CycloneDX SBOM、Linux amd64/arm64构建/sha256。规则引擎可用后规则正反例成为必跑；当前明确未实现，不得创建伪规则测试说通过。SSH/Collector/AI/证据实现后增加对应集成和负例；Web后Playwright。GitHub workflow配置存在≠远端CI已运行。

依赖和Actions版本固定，网络漏洞库不可用标基础设施阻塞，不能伪绿；SBOM只代表列出组件，不等于无漏洞。原始source manifest复核，Schema应校验正负样例/CLI实际输出，禁止只检查JSON语法。

## 证据

docs/05-testing/evidence/<本轮目录>/保存命令、退出码、耗时、输出、构建摘要/版本，测试报告按实际执行更新。后续每任务证据单独目录。不得提交凭据或实际敏感主机日志。

目录迁移/AGENTS规范当前证据在evidence/layout-migration；bootstrap是首次切片历史证据，保持原始内容。make check当前含目录与AGENTS/spec/package校验，跨工程命令显式记录cwd。
