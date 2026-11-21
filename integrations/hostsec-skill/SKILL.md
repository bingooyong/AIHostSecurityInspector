# HostSec Skill（产品分发材料）

本目录是产品 Skill 接入说明，不是检测内核。检测、授权、规则与证据仍只在 Go 内核执行。

## 允许调用

- `hostsec version|doctor|assets|plan|intent|preflight`
- `hostsec inspect-fixture --file PATH --host ID --root ABS_FIXTURE --out DIR --profile quick|standard`

`inspect-fixture` 只读取调用方提供的合成 fixture 根目录，拒绝 `/`，不设置 `collector_available`/`scan_ready`/`execution_ready`，不 SSH、不扫描企业主机。deep 与 incident-response 仍要求独立审批，本 Skill 不得代为执行。

## 禁止

- 任意 Shell、SSH exec、SQL/VQL 或外部工具任意参数
- 把模型输出直接当命令
- 外发原始日志、完整 argv、凭据或私钥
- 用空审批 ID 或两个用户名冒充审批

AI 默认关闭。若后续启用，只能发送最小化结构化字段，且引用必须落在本次允许的 evidence ID 集合内。
