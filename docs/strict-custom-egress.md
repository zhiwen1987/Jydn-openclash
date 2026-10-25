# 业务专属出口与故障断流

这项扩展在 69 个业务组下分别追加两个独立入口：`🔐 自定义节点 · 业务名` 和 `🔐 自定义节点组 · 业务名`。每个入口的默认值为 `REJECT`。没有自建节点时选择它，当前业务的新连接就会被阻断。

原有业务默认值、公共节点、公共节点池、规则及其顺序保持原样。Google、Gemini、YouTube 分别设置，不进行 Google 全族合并。现有规则中优先匹配 DIRECT 的例外继续生效；此功能约束的是实际命中该业务组的流量，不能代替域名覆盖审计。

## 文件与接入

旁路由私有文件：

- `/etc/openclash/custom/strict-custom-private.yaml`：真实节点和私有池，仅 root 读取。
- `/etc/openclash/custom/strict-custom-locks.yaml` 及 `.good`：持久绑定及备用副本。
- `/etc/openclash/custom/strict-custom-policy.json`：业务入口清单。
- `/etc/openclash/custom/jydn_strict_custom_hook.sh`：在现有覆写脚本最后执行，订阅更新和重启时重建入口。
- `/etc/openclash/custom/jydn_strict_bind.rb`：绑定、清理该业务旧连接、解除绑定的管理工具。

真实密码、Token、密钥和上述私有配置不得提交 GitHub。公开示例见 `modules/strict-custom-private.example.yaml`。普通模板更新只生成空入口；私有数据始终在旁路由本地加载。

当前生产仍使用原 R4 文件名 `精准稳定-v1-r4-ha-subscription-managed.yaml`，避免破坏现有 Grok 控制器按路径读取配置的行为。功能版本通过 Git 提交和文件摘要区分，不靠改文件名。

## 导入和持久绑定

先备份私有配置，再按示例填写节点。节点 ID 使用字母、数字、下划线或短横线，后续保持不变。节点池只允许引用已声明的私有节点，不允许 DIRECT、共享池或外部 provider。可选择 `select` 或仅在这些私有节点之间切换的 `fallback`。

在旁路由执行（将业务名替换为面板上的完整名称，包括图标）：

```sh
ruby /etc/openclash/custom/jydn_strict_bind.rb '业务完整名称' node own-us01
ruby /etc/openclash/custom/jydn_strict_bind.rb '业务完整名称' group own-primary-backup
```

节点未配置时可先绑定阻断：

```sh
ruby /etc/openclash/custom/jydn_strict_bind.rb '业务完整名称' node REJECT
```

工具先生成候选并执行当前内核校验，再将该业务置于 REJECT、关闭仅属于该业务的现存连接，保存持久绑定并热加载。绑定后，该业务外层只允许专属入口和 REJECT；公共池不再是它的合法选项。私有目标从配置中消失时转为 REJECT。即使选择缓存丢失，也不能回到公共出口。

解除绑定是明确的管理操作，会恢复保存的原业务菜单及选择：

```sh
ruby /etc/openclash/custom/jydn_strict_bind.rb '业务完整名称' unlock
```

**直接在面板点击入口**适合临时选择，仅影响新连接并依赖 Mihomo 的选择缓存；严格要求长期固定出口时，应使用上述持久绑定工具。单独的 `strict_select.py` 是 API 栅栏和连接清理工具，不承担持久绑定。

## DNS 和控制器边界

保持原上游 DNS 地址和引导 DNS。对实际业务域名规则追加 nameserver-policy，使解析传输跟随业务组，避免专属出口失效后用公共代理解析该业务。已有显式 DNS 例外保留。原本 DIRECT 默认的业务继续使用已有国内 DNS。IPv6 开关不变。

clash-center 的质量控制器识别专属入口，包括经父组继承的专属选择，取消这种选择的自动接管租期。持久绑定还通过内核成员白名单阻止选择回公共池。其他业务自动检测逻辑保持不变。

这不是整个网络的防绕过防火墙：客户端绕过旁路由、未命中业务规则的地址、额外加密 DNS，以及 OpenClash 内核整体退出时的旁路行为，需另行验收。这里不宣称覆盖这些情况，也不承诺互联网可用率。

## 验收与恢复

自动检查包括生成器校验、Ruby 编译器测试、实际 R2 质量控制器回归，以及当前生产 Mihomo 二进制在 `--network none` 容器中的真实连接/DNS测试。隔离测试只挂载合成配置，不挂载生产数据库，不关闭生产节点。

部署前分别保存源配置、运行配置、覆写脚本、UCI、组过滤器、目录清单，以及中心 Compose、原镜像标识和 SQLite 在线备份。上线期间由旁路由 procd 与 249 宿主机 systemd 的独立守护负责限时恢复；验收后停止该轮守护。

本轮备份位置：

- 旁路由：`/root/openclash-backups/strict-custom-20261026-1792948104`
- 249：`/var/backups/strict-custom-20261026-1792948105998621005`

先恢复旁路由，再恢复中心（在对应设备 root shell 执行）：

```sh
# 旁路由：核对 MAC 必须为 00:0c:29:2d:96:e8
ruby /root/openclash-backups/strict-custom-20261026-1792948104/stage/strict_custom_router_recovery.rb rollback /root/openclash-backups/strict-custom-20261026-1792948104
# 249
python3 /var/backups/strict-custom-20261026-1792948105998621005/stage/server_recovery.py rollback /var/backups/strict-custom-20261026-1792948105998621005
```

恢复工具核对备份摘要和当前受管理文件，检测到后续并发修改会拒绝覆盖。此恢复针对本轮部署的直接回退；后续已建立真实私有绑定时，应另做当时的备份，不应直接回退到旧公共出口。中心恢复保留实时数据库，不覆盖本轮上线后的监控数据。
