# PR7 授权采集 Ledger 审查与修复

日期：2026-11-25（Asia/Taipei）。基线：`0c1a7e7daeeeb45df1bbccf3d9c673dca0c66aa9`，PR7 live 为 OPEN、未合并，原 head 的 offline-cli CI success。box 既有 `/workspace/AIHostSecurityInspector-lab` 起始 clean；未触碰用户电脑、未启动云代理、未访问任何非 loopback 目标，本轮没有启动 sshd 或真实 SSH 采集。

## 审查发现与最小修复

1. **高优先级：跨进程/实例重放和更新丢失。** 原 `approval/ledger.go` 只在 Open 读取，Consume 的 mutex 只属于一个对象。RED 中两个提前打开的实例接受同一 nonce，四个提前打开的真实进程全部消费成功。现用稳定 `.lock` 侧车的非阻塞 flock，在锁内重读，不锁即将被 rename 替换的 JSON inode。竞争失败关闭，至多一个消费者成功。
2. **高优先级：直接覆盖破坏消费历史。** 原 WriteFile 会先截断当前账本；原代码先更新内存，写失败后又错误拒绝合法重试。现同目录随机 0600 临时文件、文件 fsync、rename、目录 fsync 后才成功。子进程降低自身 RLIMIT_FSIZE 至 1 字节，验证真实快照短写失败：原 JSON 字节不变，解除限制后相同 nonce 可重试，原消费记录仍拒绝重放，无遗留临时文件。未用 root 权限绕过目录不可写来假测失败。
3. **受控输入：** 拒绝最终 symlink/FIFO、硬链接、非本人文件、group/other 权限、损坏/null/超过 1 MiB 状态；每次消费检查而非只在 Open 检查。账本一旦被本实例观察为存在，消失时拒绝重建。

保留现有 JSON 字符串数组、OpenLedger/Consume 接口和显式内存 Ledger；不引入数据库/新运行依赖，不改授权采集调用顺序，不放开 deep/IR。

## 测试证据

- `red.log`：修改实现前 `go -C backend test -count=1 ./internal/approval -run TestLedger`，预期 exit 1；实际确认 stale replay、四进程放行、写失败污染与不安全文件等断言失败。
- `green.log`：第一轮 ledger race 测试 exit 0；后续补充真实短写与 FIFO/lock 攻击回归，以 `focused-race.log` 与最终全量记录为准。
- `focused-race.log`：approval/audit/planner/orchestrator/cli 五包 `-race -count=1`，exit 0。
- `frozen-contract-tests.log`：意图账本重放、非 loopback/未授权拒绝、deep 拒绝、CLI 明确非内网扫描提示，全部 PASS。
- `frozen-cli.json`：实际二进制 doctor exit 1，collector_available=false、scan_ready=false；scan 与 mcp serve exit 2；DAG 实际计数 IMPLEMENTED 36 / PARTIAL 11 / BLOCKED 1，HOSTSEC-43 BLOCKED。
- `check/`：第一次 make check 在 integration-schema 因 Python 环境缺 jsonschema 停止，保留真实 FAIL，不覆盖。
- 重跑使用 `/workspace/hostsec-ledger-venv`，仅安装 `scripts/requirements.txt` 固定的 jsonschema==4.26.0。无系统环境变更、无供应商审计工具安装/runner 审计。

## 审查结论与边界

沿 HOSTSEC-32A → HOSTSEC-07 → HOSTSEC-36 的授权/防重放关键路径补强，复用既有任务，未新建 DAG 节点或改变状态计数。代码、错误路径、格式兼容、稳定锁 inode、文件权限、同步顺序、调用方拒绝传播均做人工自审；未声称独立第三方审查。

仍需受信任的私有本地目录、同一路径及完整的账本/锁保留策略；本机所有者可改写/删除状态，不是抗管理员篡改存储，不是 NFS/多节点分布式锁，也不保证 journal 与 ledger 跨文件原子事务。新进程启动前丢失状态须人工核对，不得将新账本初始化当原意图未消费。rename 后 fsync 失败可能已消费，只能保守拒绝，不恢复旧状态。本轮验证短写恢复与真实多进程，不声称断电/内核崩溃故障注入验收。

doctor/scan/mcp serve 冻结合同不变；authorized collection 仍仅 loopback，模块成功也不标扫描就绪。HOSTSEC-43 的真实双架构 VM、平台 IdP/区域生产 runner、内网授权采集均未交付。单 amd64 box、交叉构建、fixtures 不替代该验收。未自动合并、未发 PR 评论或消息。

## 最终本地验收

`PATH="/workspace/hostsec-ledger-venv/bin:$PATH" make check HOSTSEC_EVIDENCE_DIR=docs/05-testing/evidence/hostsec-wp6-2026-11-25-ledger-hardening/check-final`：exit 0，23/23 PASS，于 2026-11-25 10:05:48（Asia/Taipei）完成。含全域 race/vet/lint、CLI/Schema、前端 E2E、安全边界、DAG/来源、漏洞、SBOM 和双架构构建；双架构构建不是双架构 VM 实跑。复核 verified-files.json 与当前源码摘要全量一致。

本报告及 frozen-cli.json 不包含私钥、凭据或原始主机载荷。CI 状态由交付时对新提交的单次 live 查询给出，不把本地 PASS 当远端结果。
