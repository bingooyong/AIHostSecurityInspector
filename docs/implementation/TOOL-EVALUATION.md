# 专业工具与依赖选型复核

核查日期2026-11-20；读取官方仓库/release/license/docs。未安装或运行扫描器；上游支持不等于HostSec验证。以下版本为观察值，实际Adapter锁版须重新核对。所有Adapter实现当前PLANNED。

| 工具 | 维护/许可（固定版本重要） | 兼容/离线/驻留/资源 | 决策与验收 |
|---|---|---|---|
| osquery | 5.24.1，2026-10-29，未归档；Apache-2.0或GPL-2.0-only | Linux x86_64/aarch64 release包；osqueryi无需daemon/可离线；权限影响表，查询CPU/IO需测 | P0，固定查询ID/SQL，禁止调用方SQL、meta commands与动态扩展 |
| Lynis | 3.1.7，2026-06-25，未归档；GPL-3.0 | UNIX/Linux Shell无需编译/驻留；目标工具/发行版决定覆盖；写日志/报告，CPU/IO待测 | P0，独立CLI，不嵌入代码；允许输出目录与副作用审查 |
| OpenSCAP | 1.4.6，2026-10-22；LGPL-2.1；SCAP/SSG独立许可 | Linux amd64/arm64发行版包；不常驻；离线内容需预置且匹配OS，probe内存配置 | P1，拒绝remediate/fetch-remote-resources，工具与内容双锁版 |
| ClamAV | 1.5.5，2026-11-18；GPL-2.0，签名库另核条款 | x86_64/aarch64包；clamscan无需daemon；离线预置库，装库/解压消耗内存IO | P1，只报告；拒绝remove/move/copy和扫描时更新数据库，缺/过期库不得PASS |
| YARA | 4.6.0，2026-10-27；BSD-3-Clause；README声明maintenance mode | Linux可源码构建；未核实官方ARM64二进制；离线不常驻，资源随规则/文件增长 | P1，保留Adapter，规则独立许可/审签/超时；YARA-X另评估不擅自替换 |
| Velociraptor | 0.77.3，2026-10-05；AGPL-3.0 | Linux amd64/arm64 release；离线collector或client/server；artifact影响资源 | P2，复用DFIR/Hunt，不开放任意VQL/命令；分发/改造网络服务审许可 |
| Wazuh | 4.14.10，2026-11-09；该版本GPLv2；main已有engine AGPLv3+/其他GPLv2与部分双授权 | Linux双架构官方包；持续功能需agent/manager/indexer；内网内容镜像；运维/存储高于CLI | P2，接已有告警/FIM/SCA，避免重建SIEM；拒绝active response |
| Falco | 0.45.2，2026-10-29；Apache-2.0，libs/驱动/插件/规则另审 | Linux x86_64/aarch64；常驻内核/eBPF依赖；预置组件可离线，事件量/丢事件待测 | P2，运行时持续检测非一次快照，本轮不安装内核组件 |

开源许可不一概禁止商业使用；修改、分发、静态/动态链接、嵌入、网络服务及内容包有不同义务。当前选择独立Adapter不等于免除分发义务。实际商业打包前按锁定版本组件生成SBOM并审NOTICE/源码提供/规则情报条款。

## 官方证据

- osquery：[release](https://github.com/osquery/osquery/releases/tag/5.24.1)、[LICENSE](https://github.com/osquery/osquery/blob/master/LICENSE)、[osqueryi](https://github.com/osquery/osquery/blob/master/docs/wiki/introduction/using-osqueryi.md)、[性能](https://github.com/osquery/osquery/blob/master/docs/wiki/deployment/performance-safety.md)。
- Lynis：[release](https://github.com/CISOfy/lynis/releases/tag/3.1.7)、[README](https://github.com/CISOfy/lynis/blob/master/README.md)、[LICENSE](https://github.com/CISOfy/lynis/blob/master/LICENSE)、[写日志源码](https://github.com/CISOfy/lynis/blob/master/lynis)。
- OpenSCAP：[release](https://github.com/OpenSCAP/openscap/releases/tag/1.4.6)、[COPYING](https://github.com/OpenSCAP/openscap/blob/main/COPYING)、[manual](https://github.com/OpenSCAP/openscap/blob/main/docs/manual/manual.adoc)、[Debian架构](https://packages.debian.org/trixie/openscap-scanner)。
- ClamAV：[release](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.5)、[COPYING](https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt)、[扫描](https://github.com/Cisco-Talos/clamav-documentation/blob/main/src/manual/Usage/Scanning.md)。官网安装页HTTP403，改读官方仓库；旧文档架构描述不能优先于最新release。
- YARA：[release](https://github.com/VirusTotal/yara/releases/tag/v4.6.0)、[maintenance mode](https://github.com/VirusTotal/yara/blob/master/README.md)、[COPYING](https://github.com/VirusTotal/yara/blob/master/COPYING)。
- Velociraptor：[release](https://github.com/Velocidex/velociraptor/releases/tag/v0.77.3)、[离线README](https://github.com/Velocidex/velociraptor/blob/master/README.md)、[LICENSE](https://github.com/Velocidex/velociraptor/blob/master/LICENSE)。
- Wazuh：[release](https://github.com/wazuh/wazuh/releases/tag/v4.14.10)、[版本LICENSE](https://github.com/wazuh/wazuh/blob/v4.14.10/LICENSE)、[main区别](https://github.com/wazuh/wazuh/blob/main/LICENSE)、[包架构](https://documentation.wazuh.com/current/installation-guide/packages-list.html)。
- Falco：[release](https://github.com/falcosecurity/falco/releases/tag/0.45.2)、[README](https://github.com/falcosecurity/falco/blob/master/README.md)、[LICENSE](https://github.com/falcosecurity/falco/blob/master/LICENSE)。

## Go依赖

`go.yaml.in/yaml/v4 v4.0.0`（2026-11-04）为YAML组织维护版本，原go-yaml/yaml已归档；Apache-2.0，libyaml派生部分保留MIT。首切片解析YAML必要依赖，严格字段/唯一key/拒绝多文档、alias/merge/深度与字节上限另行测试。来源：[README](https://github.com/yaml/go-yaml/blob/main/README.md)、[go.mod](https://github.com/yaml/go-yaml/blob/v4.0.0/go.mod)、[原归档](https://github.com/go-yaml/yaml)。

SQLite后续优先验证modernc.org/sqlite（观察v1.62.0，2026-11-07，BSD-3-Clause，纯Go双Linux架构；libc需匹配），对比mattn/go-sqlite3（MIT，需CGO）。首切片无历史状态不引入驱动。来源：[modernc](https://pkg.go.dev/modernc.org/sqlite)、[版本](https://proxy.golang.org/modernc.org/sqlite/@v/v1.62.0.info)、[mattn](https://github.com/mattn/go-sqlite3)。

## 每个Adapter的进入门禁

具体企业发行版/架构与最小权限运行、稳定输出解析、缺工具/格式不兼容/退出码/超时/资源压力、离线内容完整性、写入副作用和许可均未验证。后续任务必须逐项实测，不因上游宣称Linux/ARM64就标IMPLEMENTED。不可在扫描期间自动安装/升级工具或下载未经批准规则。
