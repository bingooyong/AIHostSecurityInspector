# Go 工程布局官方依据

核实日期2026-11-20；只读访问Go官方文档，没有安装工具或运行扫描器。

| 决定 | 官方资料与适用限制 |
|---|---|
| backend内cmd多binary | https://go.dev/doc/modules/layout ：“A common convention is placing all commands … into a cmd directory”。cmd是惯例，不是编译器强制；项目选择薄main与内部实现。 |
| 内核放internal | 同页服务布局建议internal；https://go.dev/cmd/go/#hdr-Internal_Directories 规定可见性。internal不是权限隔离，同module不阻止Collector误导入Provider，须依赖树门禁。 |
| backend/go.mod与module/backend | https://go.dev/ref/mod#module-path ：子目录module path和版本tag前缀对应子目录。当前imports统一github.com/bingooyong/AIHostSecurityInspector/backend，以后tag前缀backend/。不更改实际GitHub仓库大小写。 |
| 当前不用go.work | https://go.dev/ref/mod#workspaces ：没有go.work时只处理所属module；https://go.dev/doc/tutorial/workspaces 说明多个Go module联合开发的用途。单Go module+前端不要求go.work。 |

根Makefile用go -C backend或cwd=backend；不引入根replace/GO111MODULE兼容补丁。backend/frontend/integrations是本项目根据用户多工程要求的选择，并非“Go官方规定所有仓库必须这样分”。有独立生命周期/依赖/SDK需求后再拆module；不创建无消费者pkg。

执行风险：imports、相对fixture路径、Go工具源码、format/vet/test/lint/vuln/SBOM命令cwd、绝对产物路径、CI toolchain/cache、当前Trellis任务交付路径需一致变更。历史来源和旧验证日志保留，新的行为回归和门禁存layout-migration目录。
