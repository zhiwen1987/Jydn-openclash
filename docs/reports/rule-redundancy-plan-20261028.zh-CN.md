# 规则冗余清理方案（仅提案，不改规则）

## 结论

基线是 `Jydn-openclash` 的 `a56f233676ea5ff87cc68540fe292c01ed131363`。本提案没有修改 `rules/`、`custom/`、`upstream/`、`modules/`、`metafenliu.ini` 或任何生效输入；没有连接设备、改变本机代理/DNS/Clash 设置、部署、推送、创建 PR 或触发发布。

同时只读核对了 `clash-center` 的 `f70351ed0006c26bd53637697343098b13bc8b93`、根 `README.md` 与 `START_HERE.md`；该仓库明确把规则维护留在本仓库，本任务未在其中建立分支或提交。两个目标仓库均未找到仓库内 `AGENTS.md`；OpenClash 也没有 `START_HERE.md`、`docs/ai/START_HERE.md` 或 `docs/architecture.md`，因此按其根 `README.md` 和规则维护文档执行。发布 workflow 的 `workflow_run` 路径只接受 `main`，但另有手动入口；本任务不会调用手动发布。

对最新基线独立重算后，旧审计的 **147 个重复副本**和 **270 条静态遮蔽**仍成立。当前规则总数从旧审计的 525 增至 531，是后续已合入的 6 条规则；它们没有新增重复或遮蔽。

逐项决定已经落入机器清单。270 是完整遮蔽集合，147 是其中的完全重复子集，不能相加成 417：

| 决定 | 条数 | 处理 |
| --- | ---: | --- |
| 完整重复的条件可删项 | 147 | 更晚加载的相同匹配器；更早副本同为 `DIRECT` |
| 父后缀完全覆盖的条件可删项 | 123 | 更早同目标父匹配器覆盖该条所有可能命中；不是文本重复 |
| 非冗余域名规则 | 246 | 未证明存在更早、同目标、完全覆盖，保留 |
| 复杂或非域名规则 | 15 | IP/ASN、复合条件、多通配符等不做等价推断，保留 |

完整 531 条逐项决定见 [`rule-redundancy-inventory.json`](rule-redundancy-inventory.json)。其中现场 WebRTC 复杂条件只记录文件、行号、类型和“保留”，不复制条目内容。270 条候选及每条覆盖依据、目标、稳定 ID、原始行号和逐文件哈希前置条件见 [`rule-redundancy-candidate-operations.json`](rule-redundancy-candidate-operations.json)。该文件明确标记 `proposal_only=true`、`apply_automatically=false`，不是可直接执行的变更授权。

## 270 条候选为何仅是“条件可删”

每条候选同时满足：

1. 147 条的删除项与保留项是相同匹配器；另 123 条由更早父后缀覆盖其全部可能命中；
2. 覆盖项与被覆盖项指向同一个目标；147 条完全重复项为 `DIRECT`，开发文件内父子项保持原开发策略目标；
3. 保留规则在固定模板/provider 顺序中严格早于删除规则；可以是更早 provider，也可以是同一 provider 内更早的父项；
4. 删除项在当前完整模板中本来就不会成为首命中规则；
5. 候选只包含可静态证明的域名精确、后缀及一个固定后缀通配条件，不包含 IP、IPv6、`no-resolve`、端口、进程、复合条件或未知规则类型。

这只能证明**完整 `metafenliu.ini` 加载关系**下的冗余。跨 provider 删除会改变被删 YAML 单独消费时的成员集合；同文件父覆盖删除也会移除显式服务明细，改变维护分工和可读目录。对 123 条父覆盖项，清单逐条记录了父项位置和 `standalone_impact`，不是用“未测试”空泛略过。若第三方单独引用 `direct.yaml`、银行/政务/证券/网盘/音乐/开发规则文件，删除将改变其显式成员集合，部分文件还会明显缩小。因此，本方案不在当前 Draft PR 实施删除；后续实现 PR 前必须先盘点独立消费者，并由用户选择“仅 147 条完全重复”还是“完整 270 条固定模板冗余”。选择任一集合后都必须按最终集合重新生成证据。

15 条复杂/非域名规则全部保留，尤其不把文件体积或域名样本当成 IP/IPv6/条件规则等价证明。246 条无静态覆盖证明的域名规则也逐条标为保留。

## 假想前后对照

分析器只在内存中从 7 个 provider 文件删除 270 行；磁盘上的规则文件均没有改变。

| 样本集 | 样本数 | `actual` 变化 | `rule_line` 变化 | `rule_kind` 变化 | `rule_source` 变化 |
| --- | ---: | ---: | ---: | ---: | ---: |
| manifest 固定公共分类样本 | 2,567 | 0 | 0 | 0 | 0 |
| 每个候选的根域/精确域名及后缀子域见证 | 514 | 0 | 0 | 0 | 0 |

公共样本语料 SHA-256 是 `d2527b08a35bc338cc21dfc7cff0ee113fdc495eb4dc7a97daf923c6ff0fc301`。上游内容只从 manifest 中固定 commit 的 `raw.githubusercontent.com` 地址读取并校验 SHA-256；缓存损坏、下载失败或哈希不符都会停止，不会回退到浮动内容，也不会连接生产设备。

四个字段全部零变化很重要：本提案不是仅以最终目标相同放行；它还验证了首命中模板行、规则种类和规则源都不变。原因是候选删除项在删除前就已被更早的保留项命中。

边界：模拟只覆盖域名阶段。它不证明 IP/IPv6、端口、进程、DNS、策略组选项的运行时选择、节点或真实网络可用性；因此这些范围没有候选删除。完整结构化结果见 [`../../reports/rule-redundancy-plan-evidence-20261028.json`](../../reports/rule-redundancy-plan-evidence-20261028.json)。

## 文件体积与加载内存

以下是对候选内存副本的实际字节测量；gzip 定义为每个文件分别使用 gzip level 9、`mtime=0` 后求和：

| 范围 | 原始 bytes 前/后 | 原始节省 | gzip bytes 前/后 | gzip 节省 |
| --- | ---: | ---: | ---: | ---: |
| `rules/bank-cn.yaml` | 819 / 397 | 422 | 325 / 224 | 101 |
| `rules/cloud-drive-cn.yaml` | 975 / 793 | 182 | 372 / 318 | 54 |
| `rules/development.yaml` | 2,546 / 1,727 | 819 | 750 / 594 | 156 |
| `rules/direct.yaml` | 6,517 / 3,120 | 3,397 | 2,163 / 1,292 | 871 |
| `rules/government-cn.yaml` | 556 / 119 | 437 | 262 / 123 | 139 |
| `rules/music-cn.yaml` | 618 / 486 | 132 | 284 / 239 | 45 |
| `rules/securities-cn.yaml` | 406 / 149 | 257 | 225 / 141 | 84 |
| 全部 18 个规则 YAML | 14,570 / 8,924 | 5,646 | 6,109 / 4,659 | 1,450 |

这些数字按完整 270 条候选计算，没有把 147 与 270 叠加。它们只是文件和压缩传输体积，不等于 Mihomo 永久加载内存。

对内存只能给带参数的规划估算：270 个候选的匹配值合计 3,239 个 UTF-8 bytes、702 个域名标签。若模型为“匹配值字节 + 每条 32–96 bytes 的规则/索引对象 + 每标签 0–48 bytes 的 trie 节点增量”，结果约为 11,879–62,855 bytes；向上覆盖分配器对齐和额外索引后，可把 **0–96 KiB** 作为规划区间。下界取 0，是因为实际解析器可能跨 provider 去重、共享父节点，或节省量被 allocator page/size-class 舍入吞没；上界是模型场景上取整，不是 Mihomo 实测上限。因此本方案不能承诺会观测到 RSS 下降，更不能把 5,646 个磁盘 bytes 当作内存节省。

当前没有获得与目标基线相同版本的 Mihomo 二进制。如需把规划区间收窄，应另行提供同版本二进制，在无监听、无生产配置、隔离的 test-only 进程中，对原配置和内存候选配置分别多次冷启动，记录版本、Go runtime、稳态 heap profile/分配统计和重复测量分布；瞬时 RSS 只能作为辅证，不能单次取样下结论。

## 换行证据与工作树边界

原 clone 和隔离 worktree 均把 `rules/development.yaml`、`rules/singapore.yaml` 显示为修改。两文件的 `.gitattributes` 要求 `text eol=lf`，而 HEAD blob/checkout 过滤造成整文件换行重整化；`git diff --ignore-space-at-eol --exit-code --` 返回 0。它们不是本提案内容，不会暂存或提交。最终提交树必须再次验证没有任何规则 payload 或模板输入变化。

## 复现

```powershell
python tests/test_rule_redundancy_analysis.py -v
python tools/analyze_rule_redundancy.py --write --with-simulator
python tests/test_routing_simulator.py -v
python tools/simulate_routing.py
```

第二、三、四条命令可能读取 manifest 固定的公开 GitHub 规则；不会读取设备、局域网服务或生产 API。分析器输出文件后，必须确认 `git diff --name-only` 只包含本方案的文档、报告、分析器和测试。

本分支已通过：`tests/` 下 12 项 Python 测试、发布器 7 项 Python 测试、现有 3 组 Ruby 测试（portable Ruby 4.0.9，其中严格自定义组含 19 项断言）、`scripts/build.py` 和 `scripts/validate.py`。构建/校验没有留下生成产物差异；这些离线结果不替代生产验收。

## 后续决策

本分支只适合建立 **Draft PR**，且 Draft PR 也不包含实际规则删除。若以后决定实施，应另开实现 PR，并至少满足：独立消费者盘点、同一输入哈希前置检查、四字段全样本零变化、候选见证零变化、规则校验/构建通过、明确不触发发布和不部署。未经新的合并与部署授权，不得合并或应用候选列表。
