# 模板与规则维护

仅使用转换模板或维护规则时参考本页；完整系统见[安装说明](../installer/README.zh-CN.md)，生产事实见[部署记录](production-deployment-20261026.md)。

## 模板地址

| 内容 | 地址 |
|---|---|
| 转换模板 | `https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/metafenliu.ini` |
| DNS/隐私覆写 | `https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/modules/openclash-dns-privacy-override.yaml` |

在线转换服务能接触原始订阅。使用信任的服务或自建转换器，不将订阅、Token 和节点信息提交仓库。模板更新不等于生产已加载，须核对活动源文件和实际 API。

DNS 覆写会改变解析行为，不能当作无影响的模板附件直接套用。本次中心接管保留原 DNS。旧版 LuCI 教程见[历史说明](openclash-v0.47.156-settings.md)，当前插件版本另外核实。

## 文件职责

| 路径 | 用途 |
|---|---|
| `upstream/`、`custom/` | 上游模板与自定义输入 |
| `rules/` | 业务域名、网段等规则数据 |
| `modules/` | 可选覆写模块 |
| `scripts/build.py`、`scripts/validate.py` | 构建与静态校验 |
| `scripts/strict_custom.rb` 等 | 自定义入口编译及限制 |
| `metafenliu.ini` | 构建产物，持久修改应维护源输入 |
| `monitoring/lan-center/` | 中心模块源码及历史操作记录 |
| `installer/` | 单容器离线安装与恢复代理 |

维护前阅读相关脚本参数和 CI，修改输入后运行构建、校验及对应回归，审阅生成差异。域名规则按顺序匹配；国内、海外、私网及用户例外一起测。避免为单个共享 CDN 域名宽泛绑定整个 ASN。

模板、provider、源配置、运行配置和 API 图是不同层次。判断流量出口应查看新连接实际规则和完整 chains，而不是只看模板或节点名称。

自建节点使用 3103 持久入口；手工添加到机场下载文件可能被覆盖。唯一自定义入口及故障断流边界见[说明](strict-custom-egress.md)。
