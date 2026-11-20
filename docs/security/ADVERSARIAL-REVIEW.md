# 对抗式审计 — 本轮基线与离线CLI

日期2026-11-20。范围为设计基线及HOSTSEC-03A；未来运行控制不冒充已验证。独立代码审查见 [CLI-INDEPENDENT-REVIEW](CLI-INDEPENDENT-REVIEW.md)。完整本地门禁结果见 [results](../05-testing/evidence/bootstrap/results.json)。

## 本轮已复现并修复

| ID / 等级 | 复现方法 | 影响 | 修复建议与实施 | 修复/回归证据 | 状态 |
|---|---|---|---|---|---|
| CR-01 低 | 有效JSON local connection加入port/user/auth_ref/known_hosts_ref:null；原CLI接受但Schema拒绝 | 解析契约不一致，无执行器 | 在JSON token和YAML节点层拒绝显式null | asset.go、TestRejectNullConnectionScalars（JSON/YAML八例）及独立CLI复验；race日志 | IMPLEMENTED |
| CR-02 中 | 主机ID与组引用同步改为192.0.2.10，原plan可接受裸IP形ID | 稳定主机身份契约破坏，原仍要求登记授权 | ValidHostID排除netip地址；资产/组ref/计划Schema同步 | TestHostIdentityCannotBeIPAddress、Schema反例及独立CLI exit2复验 | IMPLEMENTED |
| DR-01 中 | 后续任务manifests只含通用三文档，漏模块SDD | 后续代理可能错过接口/错误/资源边界 | 48节点input_documents与PRD/两manifest补模块SDD | validate_baseline.py全部节点/上下文路径校验 | IMPLEMENTED |

## 用户要求的13项覆盖

| 风险 / 等级 | 复现或后续验证方法 | 影响范围 | 控制/修复建议 | 当前证据及回归 | 状态 |
|---|---|---|---|---|---|
| 1 参数注入 / 高 | --exec/--command、目标含分号、裸IP段、未知命令 | CLI/Agent/未来Adapter | 拒绝非业务flags/目标，无执行器；后续固定argv | CLI/Integration27进程+AST无os/exec；未来40 | PARTIAL（当前切片通过） |
| 2 主机Prompt Injection / 高 | 文件名/日志要求运行命令或外发secret | AI/Skill | 视图allowlist、无tool calling、结构化输出/ref、Agent合约 | 当前无模型或主机输入；25–29注入测试待运行 | PLANNED |
| 3 SSH Host Key绕过 / 高 | 配置insecure、远程mismatch/未知key | SSH身份 | strict配置与真实known_hosts回调，失败关闭 | 当前配置负例通过；14真实SSH待验 | PARTIAL |
| 4 sudo过大 / 高 | 可改Collector目录、sudo任意args/ALL | 特权采集 | 固定root-owned入口/父目录/参数与最小sudo | 当前无sudo路径；14安装/VM权限审计待验 | PLANNED |
| 5 未授权扫描 / 高 | mixed组/未知host/Profile不允许/执行前撤权 | 所有入口 | 全组原子拒绝、执行复核、RBAC | 当前计划拒绝测试通过；扫描/45权限待验 | PARTIAL |
| 6 密码Token上传 / 高 | canary配置/日志/Provider重定向捕获请求 | AI/日志 | 禁内联secret，安全错误，AI默认关/最小脱敏 | 当前canary错误不泄漏且无网络客户端；26外发待验 | PARTIAL |
| 7 伪造结果 / 高 | 假来源/错签/nonce重放/跨host-scan包 | Runner/导入 | 身份签名/信任根/反重放/引用验证 | 无导入与扫描；31/41待验，hash不作真实性证明 | PLANNED |
| 8 篡改证据 / 高 | 修改字节/manifest/删对象/重算伪清单 | Evidence/报告 | 双摘要/manifest、签名与来源独立验证 | 未来结果Schema形状反例不是完整性实现；16/18/41待验 | PLANNED |
| 9 失败显示PASS / 高 | 权限/工具缺失/timeout/无基线 | Collector/规则 | 独立状态、RuleResult UNKNOWN、无证据不Finding | 当前doctor非就绪/plan不产生结果；17/36故障矩阵待验 | PARTIAL |
| 10 资源耗尽 / 高 | 超1MiB/1001hosts/深嵌套/aliases/FIFO；未来扫描压测 | 输入/扫描器 | 字节/深度/记录界限，未来时间/IO/文件/并发/压力守卫 | 当前边界单测及1000hosts本机基准；扫描限额仅描述不执行 | PARTIAL |
| 11 路径穿越 / 高 | 输入路径symlink/FIFO；未来tar../挂载/输出逃逸 | 文件/Bundle | 当前只读普通资产文件且拒symlink；未来受控对象ID安全解包 | TestLoadBoundariesAndCancellation；15/37/41待验 | PARTIAL |
| 12 规则供应链 / 高 | 恶意YAML DSL/签名/规则include或超时 | Rules/Tools | 固定来源版本签名/有限DSL/正反例/许可 | 当前无规则加载；17/24/42待验 | PLANNED |
| 13 误报未审批处置 / 高 | 调用kill/delete/firewall或模型指令动作 | 所有入口 | 没有处置接口；未来独立模块/权限/人工审批 | 当前无任意执行、处置和扫描命令，未知入口非零；未来逐入口审计 | PARTIAL |

## 供应链与限制

govulncheck最终退出0：当前调用代码和导入包均0已知可达漏洞，但Go1.27.3标准库存在未被本CLI导入的 **GO-2026-6859（net/http MaxBytesReader竞态，1.27.4修复）**。这不是“所有组件零漏洞”；记录风险R14，新增HTTP Provider/MCP/API前升级受支持工具链并重扫。原全局govulncheck源码分析组件不兼容Go1.27的首次失败保存在attempt1日志；已用固定v1.6.0在仓库build/tools内重建，没有替换用户全局安装。

本轮不连生产、不扫IP、不用真实恶意样本、不调用模型。未复现不代表不存在；当前无未修复切片内发现，但未来远程执行/证据/AI/工具的动态安全测试全部保留对应PLANNED门禁。主机root可伪造快照，READ_ONLY存在批准输出/atime/登录审计副作用，任何报告必须披露能力与盲区。
