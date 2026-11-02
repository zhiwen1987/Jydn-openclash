# P207 来源契约 v4：受控源码集成

本批以 `acabcb18509eac723c0e88664e83a019e075d474` 为开发基线，仅改变九个来源检查、模型和工作流文件；未改变 Go 产品源码。A1、联合诊断、时间线候选均不属于本批代码。

## 实际完成

- 来源契约将新增源码测试集合 S 与默认必跑集合 Q 分开，S/Q 当前均无损保留旧 43 项。历史源码 453 项与必跑 448 项的数量和摘要在检查器内独立固定，不能随契约协调重算绕过。
- 默认构建标签严格为空。完整工作流的正向模板指纹只开放 19 个精确命名、顺序、唯一性和格式受限的 pin 值；其余执行面字节必须一致，pin 实际值另行核验。它不声称能授权恶意修改后的检查器，也不证明尚未执行的环境。
- CLI 实际输出保持批准的 22 键顺序。Event/Failure 读取器同步采用 v4，官方 go-list 检查器字节未改，预算、禁止跳过、格式、失败与 fresh 门未放宽。
- 独立源码复审允许受控集成。主代理集成后再次执行 81 项纯 Python 模型，零失败，实际日志名单与源码 AST 一致，九个文件执行前后字节不变。
- 主代理运行生产用来源检查器，830 module / 21 fixture / 496 source tops / 491 required tops / 29 changed-Go 的闭包通过；`goExecutionProven` 仍为 false。

## 证据

- [独立源码复审](evidence/sys07-p207-v4-source-accepted-20261103.json)
- [集成后主代理模型](evidence/sys07-p207-v4-root-models-20261103.json)
- [集成后实际来源检查](evidence/sys07-p207-v4-root-source-20261103.json)

源码冻结 manifest 为 `1b877b99d00c9f6495ce112ee0cc45ae3c0ba3cda09278a01999f8e28dc2a1c0`，补丁为 `0efc92e0487dadc2e1d501e333376d24db57277d459ca61b8d76c5a24b9f08b6`。九个前像已逐字节备份到外部 `D:/CodexData/workspace/chengwang-p207-v4-root-preintegration-backup-20261103-cd03-v1`。失败的 v1、模型断言及包装器失败保留，没有被后续通过覆盖。

## 未完成与发布边界

本批没有在本地运行 Go、gofmt、服务或浏览器。最终新提交仍须获得自己的隔离 Linux Go、官方格式、official selection、source before/after 及 fresh 原件；旧 acab 的 491 或 31 链接受不能代替新提交验收。

A1 已接受源码候选但尚未随本批集成、编译或取得 actualfs 证据；联合诊断和时间线仍有源码修订。完整企业系统、互联网业务、灰度及生产读回均未完成。原项目 main、Registry 与生产环境未修改。Hy-Memory 工具不可用，未声称写入共享记忆。
