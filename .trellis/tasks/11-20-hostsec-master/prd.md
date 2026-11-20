# HostSec 主控需求

## 目标
建立独立企业主机巡检平台：确定性采集/检测、证据闭环、可选AI，CLI/Skills/MCP/API共用内核。

## 本轮范围
先盘点既有仓库与22份V1来源；持久化需求、架构、安全、SDD、ADR、完整WP0-WP7 DAG和MVP验收；无阻塞继续本地离线CLI首切片。用户已明确授权该范围，后续“继续”确认任务创建与本轮推进。

## 验收
本轮12项交付见执行报告；MVP-1至6和AC01-15逐项状态分离。不可把规划、fixture、编译或历史证据冒充Linux运行验收。

## 约束
READ_ONLY，未授权不扫描、不连接生产、不运行真实恶意样本、不任意Shell、不上传敏感原始数据；禁止自动处置、关闭host key和把UNKNOWN当PASS。

## 后续
MCP/Runner/平台化为独立阶段，具体主机和审批环境未提供，不属于本轮连接范围。

## 当前用户修订
Go工程迁入backend，明确CLI/Collector/Agent/API/MCP/Runner/前端与集成边界；同步构建、CI、Trellis及WP1近期详细规划。按REPOSITORY-LAYOUT与ADR-008实施，现有CLI行为不变；历史源/测试证据保留。
