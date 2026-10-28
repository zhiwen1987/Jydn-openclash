# 规则质量审计（2026-10-28）

## 结论

本轮只审计，没有修改规则、模板或加载关系。审计基线为 `f83ff23`，覆盖 `rules/` 下 18 个 YAML 文件。

| 指标 | 结果 | 解读 |
| --- | ---: | --- |
| 规则条目 | 525 | 包含域名、ASN 及 classical 条件 |
| 可静态解析的域名匹配器 | 510 | 用于后缀覆盖分析 |
| 重复副本 | 147 | 147 个值各多出 1 份；均为同路由 |
| 被更早仓库规则完全覆盖 | 270 | 按生成模板顺序同时考虑 `custom/rules.ini` 内联规则；均为行为等价冗余 |
| 本地文件跨目标冲突 | 0 | 未发现同一域名在本地加载顺序中被不同目标抢先 |
| 确认的域名注册过期 | 0 | 未用 NXDOMAIN、HTTP 超时或单次探测推断注册过期 |

详细记录：

- [`rule-quality-duplicates.csv`](rule-quality-duplicates.csv)：147 条重复副本。
- [`rule-quality-shadowing.csv`](rule-quality-shadowing.csv)：270 条静态必然遮蔽记录，其中 161 条首先被 `custom/rules.ini` 的内联规则覆盖。

`webrtc-client.yaml` 中的站点特定匹配值只参与结构计数，新增审计文件不复制其值。

## 重复与静态遮蔽

这 270 条不是 270 个分流错误。在当前加载顺序中，它们的更早规则与被遮蔽规则目标相同，因此不会改变出口。其中 147 条同时是完全重复副本，另有 123 条是不同文本表达的父后缀覆盖。影响是维护成本和人工阅读成本，不是当前命中准确率。

主要来源：

- `direct.yaml` 重复收录了早于它加载的银行、政务、证券、网盘和音乐域名。这些文件最终都是 `DIRECT`。
- `custom/rules.ini` 中更早的 `DOMAIN-SUFFIX,cn` 已覆盖后续规则文件里所有 `.cn` 条目。它们都是 `DIRECT`，所以这是静态必然但行为等价的遮蔽。
- `government-cn.yaml` 的 `+.gov.cn` 已覆盖同文件内多个具体 `gov.cn` 子域。
- `development.yaml` 中 `+.ubuntu.com`、`+.docker.io`、`+.maven.org` 等父后缀已覆盖后面的具体子域。这些明细可以作为人类可读的服务清单，但对匹配结果没有额外作用。

清理应单独开 PR，并先决定是保留“可读的明细枚举”，还是追求“最小规则集”。两者对当前出口行为等价，但维护策略不同。

## 依赖外部数据的冲突

下列项目不纳入“仓库静态必然遮蔽”的 270 条，因为它们依赖会变化的第三方规则或 GeoSite 数据。

| 项目 | 当前证据 | 结论 |
| --- | --- | --- |
| `iq.com` | 模板的第三方直连源早于“海外影音”；审计时的上游修订 `ce36489` 包含 `+.iq.com` | 在该上游快照下会被直连抢先；上游可变，所以标为“快照确认” |
| `fonts.googleapis.com` | v2fly 的 Google 源数据将它标记为 `@cn`；模板的 Google 直连分类早于 Google 业务组 | 存在被早期 GeoSite 直连抢先的条件；仓库无法证明运行时实际 geodata 版本 |
| 游戏域名 | 模板中“海外影音”早于游戏组；是否重叠由 GeoSite 数据决定 | 记录为用户提供的已知问题，本轮没有连接设备复核；修复需改设备 YAML，需老板单独同意 |

参考快照：[Aethersailor 直连规则 `ce36489`](https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/ce364895f9b55317159b43c0397788933f0f8448/rule/Custom_Direct_Domain.yaml)；[v2fly Google 域名源](https://github.com/v2fly/domain-list-community/blob/master/data/google)。

## 过期与遗留域名

“服务已退役”、“旧域名仍重定向”和“域名注册过期”是三种不同状态。本审计不用 DNS 失败或单次 HTTP 失败判定域名过期。

| 条目 | 分类 | 证据与建议 |
| --- | --- | --- |
| `homebrew.bintray.com` | 已退役服务 | JFrog 确认 Bintray 于 2021-05-01 停服。可列入后续清理 PR，但删除前仍应核对是否需要兼容历史客户端。 |
| `k8s.gcr.io` | 遗留且冻结，尚非注册过期 | Kubernetes 已将其重定向 `registry.k8s.io`，2023-04-03 后不再更新镜像。保留可兼容旧镜像引用；不建议仅因“旧”就直接删除。 |
| `pypi.python.org` | 遗留且重定向，尚非注册过期 | PyPA 说明旧域名上传于 2017-07-03 停用，`pypi.org` 于 2018-04-13 成为 PyPI 的 URL；旧域名浏览链接仍重定向。建议保留兼容性，或在有使用数据后再清理。 |

一手证据：[JFrog Bintray 停服说明](https://jfrog.com/blog/into-the-sunset-bintray-jcenter-gocenter-and-chartcenter/)；[Kubernetes 镜像仓库迁移说明](https://kubernetes.io/blog/2023/03/10/image-registry-redirect/)；[PyPA PyPI 域名迁移说明](https://packaging.python.org/en/latest/guides/migrating-to-pypi-org/)。

## 命中率前后对比

本轮没有改动规则，因此“修改前/修改后命中率”不适用，路由结果保持不变。样本命中率应由分流样本集任务统一计算，不用“重复数”伪装成准确率。

## 风险

- 删除同路由重复项通常不改变现有行为，但会减少服务明细的可读性，也可能改变某个文件单独被复用时的完整性。
- 第三方规则和 GeoSite 会独立更新；快照中成立的冲突可能在上游变更后消失或新增。
- 仅依靠仓库无法确认设备实际加载的 geodata 版本；本轮按约束没有连接任何设备。

## 需要决定的事

1. 是否单独开清理 PR，删除 147 个重复副本和/或 123 个额外的父后缀冗余。建议优先只清理跨文件重复，保留开发服务的可读明细。
2. `homebrew.bintray.com` 是否纳入后续清理 PR；`k8s.gcr.io` 和 `pypi.python.org` 建议暂保留兼容性。
3. 游戏组被“海外影音”抢先需改设备 YAML；DNS `DOMAIN-SUFFIX` 键需改为 `+.x` 需改设备覆写。两项只记录，必须由老板单独同意后再处理。
