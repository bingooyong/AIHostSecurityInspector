# 本轮验收结果

> 时点说明：本文记录首次bootstrap时的目录与验证；当前Go工程已迁入backend/，当前布局见docs/02-architecture/REPOSITORY-LAYOUT.md，新验证见evidence/layout-migration，原bootstrap日志保留。

2026-11-20。本轮模式 BOOTSTRAP + INVENTORY + DESIGN；首切片仅离线CLI。正式本地结果见 [results.json](evidence/bootstrap/results.json)，每个命令/退出码/日志持久化。远端CI未运行，Linux Collector未实现/未运行。

| AC | 状态 | 本轮证据与缺口 |
|---|---|---|
| AC-01 CLI | IMPLEMENTED（首切片） | build/hostsec真实运行；27个CLI进程；version/assets/plan/doctor |
| AC-02 未授权不可扫描 | PARTIAL | 计划层未知/未授权/混合组/Profile拒绝；尚无扫描器可验 |
| AC-03 完整dry-run | PARTIAL | 四Profile、模块/工具/资源/审批/限制，schema通过；执行计划版本/能力检查/审批绑定后续 |
| AC-04 Linux真实采集 | PLANNED | 尚无Collector；双架构ELF构建不作为采集证据 |
| AC-05 结构化进程 | PLANNED | 09/43待实施 |
| AC-06 网络PID关联 | PLANNED | 10/43待实施 |
| AC-07 规则正反例 | PLANNED | 17/44待实施；未伪造规则PASS |
| AC-08 Finding真实证据 | PLANNED | 未来Schema限制非空引用仅形状验证；引用成员/同scan-host待16/18 |
| AC-09 SHA256 | PLANNED | 源文件/产物hash已用，但不等于Evidence/manifest实现 |
| AC-10 AI引用真实性 | PLANNED | 默认无AI，不声称防幻觉模块完成 |
| AC-11 AI故障降级 | PLANNED | 尚无报告/Provider；本地HTTP故障测试后续 |
| AC-12 只读无意外变更 | PARTIAL | 当前无执行/网络与处置入口；真实Linux前后快照/工具副作用待验 |
| AC-13 无任意Shell | PARTIAL | 当前CLI负例/AST/独立审计通过；SSH/Skill/MCP/Adapter尚待上线审计 |
| AC-14 文档代码一致 | IMPLEMENTED（当前范围） | 基线/链接/来源/Schema/独立审查通过，未来变化持续复核 |
| AC-15 可扩展 | PARTIAL | asset/policy/planner/cli解耦；Collector/Rule/Analyzer扩展演示待实现 |

## 本地测试与资源

格式/vet/race/lint/AST/真实CLI与Schema/未来Schema形状/DAG和来源/依赖漏洞/SBOM/双架构构建/空白门禁通过。govulncheck零可达漏洞，但stdlib有1条不被导入路径的GO-2026-6859，见安全审计及vulnerability.log。依赖校验go mod verify退出0，environment.json记录工具版本。

1000主机JSON（547039字节）在本机Darwin arm64/Apple M1 Pro单次CLI校验约25.6ms、最大RSS14057472字节（约13.4MiB）；三次Go基准约14.5–14.7ms/op、约6.66MB累计分配/op，不是RSS。该样本低于本轮候选解析预算，不能推断Collector/扫描器资源表现；详见resource-sample.json与parse-benchmark.log。未执行持续负载或Linux资源验收。

## 未完成门禁

MVP1–6整体尚未交付。SSH认证/指纹真实服务、权限不足Collector、外部扫描器工具缺失、规则正反、证据篡改/来源、AI故障/脱敏/注入、资源守卫、签名离线包、真实测试主机试点均PLANNED；企业资产/环境/窗口/外发政策未提供时对应运行验收BLOCKED。CI配置存在与本地命令通过不表示远端GitHub运行通过。
