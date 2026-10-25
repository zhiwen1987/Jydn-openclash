# 业务专属出口与故障断流

当前版本只保留一个全局入口：`🔐 自定义节点`，没有业务后缀，也不再生成单独的“自定义节点组”。69 个业务组按需引用同一个入口；这些引用不是新的组定义。旧的 138 个重复入口和引用会在编译时清除，订阅更新后不会再次生成。

配置可以留空。未配置时入口只有 `REJECT`；选择它的业务会断流。节点配置后在这一处统一选择；所有使用它的业务会一起跟随选择，其他业务保持自己的出口。单节点失败不自动改走其他出口；如主动配置私有 fallback 池，只在该池批准的私有节点间切换。

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

工具先生成候选并执行当前内核校验，再阻断入口、关闭该业务及当前共享入口用户的旧连接，保存持久绑定并热加载。修改共享目标会影响所有使用它的业务。绑定后，该业务外层只允许共享入口和 REJECT；公共池不再是合法选项。入口默认 REJECT，因此选择缓存丢失或私有目标消失时保持断流。

解除绑定是明确的管理操作，会恢复保存的原业务菜单及选择：

```sh
ruby /etc/openclash/custom/jydn_strict_bind.rb '业务完整名称' unlock
```

**直接在面板点击入口**仅影响新连接并依赖 Mihomo 的选择缓存；要求跨重启严格固定出口时，使用上述持久绑定工具。生产管理入口统一使用旁路由工具；容器旧版 `strict_select.py` 不是本版本的管理接口。

## DNS 和控制器边界

保持原上游 DNS 地址和引导 DNS。对实际业务域名规则追加 nameserver-policy，使解析传输跟随业务组，避免专属出口失效后用公共代理解析该业务。已有显式 DNS 例外保留。原本 DIRECT 默认的业务继续使用已有国内 DNS。IPv6 开关不变。

本轮不更换或重启 clash-center，不改变节点健康判断机制。当前质量策略的人工选择租期为 0（不自动收回），已用真实控制器回归核验；该条件是本版本的上线检查项。持久绑定另以内核成员白名单阻止回公共池。未来若改变人工选择租期，需要重新验收。

这不是整个网络的防绕过防火墙：客户端绕过旁路由、未命中业务规则的地址、额外加密 DNS，以及 OpenClash 内核整体退出时的旁路行为，需另行验收。这里不宣称覆盖这些情况，也不承诺互联网可用率。

## 验收与恢复

自动检查包括生成器校验、Ruby 编译器测试、实际 R2 质量控制器回归，以及当前生产 Mihomo 二进制在 `--network none` 容器中的真实连接/DNS测试。隔离测试只挂载合成配置，不挂载生产数据库，不关闭生产节点。

部署前保存源配置、运行配置、覆写脚本、私有输入及绑定注册表、安装的编译器/工具、UCI、过滤器和目录清单；249 保存中心元数据与 SQLite 在线备份。只热加载旁路由，不更换内核，不修改 DNS，不重启容器。上线期间旁路由独立 procd 守护负责限时恢复；验收后停止。

本轮备份位置：

- 旁路由：`/root/openclash-backups/shared-custom-20261026-1792954903`
- 249：`/var/backups/shared-custom-20261026-1792954905488406897`

在目标旁路由 root shell 恢复本轮修改：

```sh
# 旁路由：核对 MAC 必须为 00:0c:29:2d:96:e8
ruby /root/openclash-backups/shared-custom-20261026-1792954903/stage/strict_custom_router_recovery.rb rollback /root/openclash-backups/shared-custom-20261026-1792954903
```

恢复会还原本轮修改的配置和工具（包括旧的多入口布局），不会覆盖实时监控数据库。工具核对摘要，检测到后续并发修改会拒绝覆盖。后续已导入真实私有节点或绑定时，应使用当时的新备份，不直接回退本轮旧状态。
