# Linux Collector 与工具 Adapter 详细设计

状态：PARTIAL。rooted Linux fixture 已实现 host_identity、process_inventory、network_inventory、account_inventory、service_inventory、persistence_inventory；doctor.collector_available 仍为 false，无真实主机/双架构 VM 验收，不采集当前工作站或连接测试/生产主机。首期目标 Linux x86_64/ARM64，发行版支持须由实际 VM/容器矩阵证明。Windows 独立后续任务，不以空接口宣称支持。

## 1. 调用契约

建议窄接口：`Collect(ctx, ModuleRequest) (ModuleResult, error)`；ModuleRequest 只有 scan_id/attempt_id/host_id、固定 module_id、Profile、受信策略版本、路径 scope 和 Limits，不接受命令、SQL、脚本或任意环境变量。ModuleResult 含 module_id、版本、start/end、status、completeness、records、raw evidence refs、warnings 和 error_code。已识别的权限不足/工具缺失记录为模块结果；通道中断等执行故障另返回 error，编排器仍保存失败元数据。

每个模块有独立 deadline、输出字节/记录上限；外层总时限更短时优先外层。context 取消后不派发新任务，当前读取/子进程在有界时间结束。结果按记录稳定排序，允许与真实采集竞争相关的 transient 标志，不伪装为稳定快照。

## 2. 采集矩阵

| 模块 | 来源与标准化字段 | 失败/竞争处理 |
|---|---|---|
| host_identity | `/etc/os-release`、uname/受控系统 API、`/proc`、`/sys`；OS/version/kernel/arch/boot time/CPU/memory/disks/身份指纹 | machine-id 等只保留受控摘要；容器视图和主机视图分别标识 |
| process_inventory | `/proc/PID` 元数据；pid/ppid/uid/name/exe path/start time/argv summary/exe_exists/hash | PID 退出或复用须用 starttime 复核；ENOENT 与 EACCES 不等价；内核线程无 exe 不误报 |
| network_inventory | 本机 socket/route/netlink 或固定受控查询；protocol/local/remote/state/inode/pid refs/routes/DNS/firewall | socket→进程关联权限或命名空间受限记 unresolved；不发连接探测包 |
| account_inventory | passwd/group、sudoers 可读片段、authorized_keys 指纹/元数据、授权登录记录 | 不采私钥/shadow 密码散列；不可读 sudo/日志记 partial；不执行登录测试 |
| service_inventory | systemd 固定属性或 unit 文件解析；unit/state/user/exec path/owner/mode/source | 非 systemd 发行版明确 N/A 或替代采集；不调用 start/stop/reload |
| persistence_inventory | systemd timers、cron/at 元数据、rc.local、shell profiles、启动脚本、内核模块 | 文件内容是不可信数据不执行；at/systemd 查询工具缺失记 not_available |
| security_config | SSH/sudo/PAM/audit/SELinux/AppArmor/firewall/syslog 的批准字段与关键文件摘要 | include/Match 的有效配置需按支持范围解析，不能将片段当整体有效值 |
| package_inventory | 本地包数据库、固定 dpkg/rpm 查询；name/version/release/arch/source | 按发行版版本语义；无支持解析器 UNKNOWN，不自动更新包 |
| targeted_file_scan / file_integrity | 白名单路径的 lstat/owner/mode/size/hash、SUID/SGID/隐藏可执行项 | 不追随越界符号链接、不跨排除挂载；截断/改动竞争记 partial |
| log_analysis | 明确授权文件/时间窗/事件类型的摘要 | 原始日志仅本地，限制行数/总字节；权限不足/日志清理迹象分别表达 |

quick 含前七模块。standard 加 package_inventory、vulnerability_correlation、baseline_assessment、targeted_file_scan；deep 再加 file_integrity、yara_scan、log_analysis。IR 使用批准的定向模块与时间窗，不自动扩大为全盘 deep。

## 3. 工具 Adapter

建议接口按 Name/Version/SupportedPlatforms/CheckAvailability/Execute 划分，执行入参为受信 `ToolOperation` 与 Profile/Scope/Limits，不能公开 raw args。ToolResult 记录版本、数据库/规则内容版本、固定 operation_id、退出码、stdout/stderr 摘要引用、解析状态、时限和证据引用。工具不存在、版本不支持、内容缺失/过期、权限不足、超时、退出码异常、输出截断和解析失败分别分类。

执行使用固定绝对二进制和参数数组，不拼 shell，不从 PATH 选择可写二进制，不继承不必要环境。读取输出有界；取消须处理子进程组，不能残留扫描进程。工具代码和内容包的版本/摘要/许可证单独登记，扫描期间不下载更新或安装。

| Adapter | 允许面 | 显式拒绝 |
|---|---|---|
| osquery | 代码内固定 query_id/SQL，一次性采集 | 调用方 SQL、meta commands、动态扩展加载 |
| Lynis | 经逐版本审查的审计测试集合；日志/报告写批准目录 | 自动修复、未知插件/测试集合、不受控输出位置 |
| OpenSCAP | 匹配 OS 的本地内容只评估 | remediate、fetch-remote-resources、未知外部引用 |
| ClamAV | 白名单目录只报告，固定离线签名库 | remove/move/copy、实时更新、越界路径/压缩解包无限制 |
| YARA | 经审查且摘要固定的规则包，受限文件匹配 | 用户临时规则代码、网络取规则、越界/无预算扫描 |

## 4. 资源默认与真正执行

初始安全默认与 plan 使用同一 policy catalog；固定 CLI 默认数值见 CLI-SDD 和实际计划输出。调度器上线时必须实施总/模块 deadline、并发、文件数/大小/总字节、递归深度、IO 速率与压力阈值；配置缺失不得无上限。维护窗口以时区明确的起止验证，deep/IR 无有效窗口不得运行。默认排除数据库数据/备份/网络挂载与伪文件系统；`/proc` 等固定系统元数据读取由专门模块控制，不进入递归文件扫描。

压力阈值或磁盘不足立即停止新文件/模块，落盘当前状态，记录阈值、测量来源与未覆盖数。限流仅显示在计划中不算实现；需要真实 CPU/RSS/IO、取消延迟和进程清理证据。

## 5. 验证与限制

fixture 测文件格式、权限、PID 竞争、关联失败、恶意长行、路径变化和上限；Linux VM/容器实跑核对进程/监听与人工读数；x86_64 和 ARM64 各自运行，不能以交叉编译替代。SSH 测试单独验证认证/指纹/超时。工具每个版本验证缺失/权限/退出码/超时/解析/只读副作用，使用 EICAR 与无害 YARA 样本，禁止真实恶意样本。

失陷内核、权限不足、命名空间隔离、短生命周期、加密/无文件恶意行为都会形成盲区。隐藏进程仅能通过 `/proc` 与独立可得视图交叉比对得到异常信号；没有可信独立视图则 UNKNOWN，不能宣称排除 Rootkit。
