# HOSTSEC-07 — 版本化策略、计划与执行前复核

日期2026-11-20；交付状态 **PARTIAL**。本次只细化规划，未声称新增业务实现或测试结果。目录契约统一为backend单Go module；所有路径均为仓库根相对路径。

## 目标与当前事实

- R07-1：策略包版本化、严格解析、四Profile固定安全语义，quick/standard/deep继承一致，IR按事件定向，不隐式变为全盘。
- R07-2：计划固定资产/策略/模块/工具/范围/资源/审批/主体/有效期，并形成可重算的规范化摘要；同意图hash稳定，任何安全相关变化导致旧审批失效。
- R07-3：离线plan从不连接主机，不能凭调用方execution_ready声明执行许可；执行前重授权、审批、窗口、身份、能力、资源状态都必须复核。
- R07-4：deep/IR要求可验证有效审批、维护窗口、文件/IO/并发/timeout/压力控制；无执行器时只显示未强制，不能说已满足。
- R07-5：执行前验证与实际调度运行分开，运行及资源压力动态验收由36/37/40汇合。

## 前置与输入

DAG前置：HOSTSEC-06, HOSTSEC-32A。父子树不代表依赖；实现前读取其真实完成证据。部分任务已有03A贡献，不因此视为全项验收通过。

- `docs/03-sdd/CLI-SDD.md`
- `docs/03-sdd/DOMAIN-MODEL.md`
- `docs/03-sdd/COLLECTOR-SDD.md`
- `docs/04-security/SECURITY-BOUNDARIES.md`
- `docs/02-architecture/REPOSITORY-LAYOUT.md`

## 交付范围与所有权

实施时由单一任务负责人协调以下文件；共享文件（Schema、CLI、脚本、Makefile）与并行任务串行集成，不能互相覆盖：

- `backend/internal/policy/`
- `backend/internal/planner/`
- `schemas/plan-v1.schema.json`
- `schemas/policy-v1.schema.json`
- `policies/`
- `backend/internal/planner/testdata/`

未来/尚不存在的交付文件在本PRD中是计划，不作为当前代码存在的证据。Go源码不回到仓库根；前端/常驻Agent/平台服务不以空工程形式凑交付。

## 验收矩阵

| 判据 | 计划测试 | 负例/禁止通过 |
|---|---|---|
| 四Profile | 固定继承集合、IR定向、每Profile审批 | deep遗漏standard、IR自动全盘、关闭READ_ONLY |
| 策略解析 | Schema+Go正反fixture、大小/字段/唯一键限制 | 任意command/SQL、未知module/tool、负数/溢出/重复值 |
| 范围/资源 | 路径/排除挂载/文件数大小/字节/IO/并发/时限完整 | /、DB/备份/网络挂载默认放开，排除被覆盖、上限缺失 |
| 计划摘要 | 固定04intent向量、顺序/字段变更矩阵 | 移除预算/审批字段不改hash，重复字段/不支持版本 |
| 审批绑定 | 使用32A验证器与相同plan_hash的授权fixture | 伪/过期/撤销/跨目标/同人/重放审批 |
| 执行前复核 | asset/policy/identity/clock/capability/pressure fake只读接口 | 变更后继续旧计划；未知能力当可用；压力缺失按正常 |
| 无执行器的诚实性 | 当前plan兼容和新校验结果 | 返回ready=true然后没有守卫，伪造scan_id或PASS |

## 不在本任务

生产或未授权主机连接、自动处置、任意Shell/SQL、安装扫描器或常驻Agent、外发敏感原文、未经授权远端发布均不在范围。未来依赖尚未实现的运行链路必须单独集成验收，不能用fixture或交叉编译替代。

## 风险与未决进入条件

策略白名单和签名不是工具无副作用证明；Preflight与启动存在TOCTOU；同一句ready标志不能代替运行限额；资源遥测未知需要明确处理。

未知若只影响未来真实部署则保留对应gate；若影响签名/身份/兼容等当前契约，先收敛设计再实现，不能由Agent猜测环境。
