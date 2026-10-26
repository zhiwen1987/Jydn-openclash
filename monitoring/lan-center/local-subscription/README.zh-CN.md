# 3103 本地自建订阅：使用与恢复

本功能复用订阅管理页，不增加生产容器。自建订阅有自己的数据、版本和发布指针；两个公共订阅继续使用原来的发布、准入与观察期逻辑。

## 添加与使用

1. 打开 `http://10.88.0.249:3103/`，在页面下方找到「本地自建订阅」。
2. 在 249 的 SSH 终端执行以下只读命令，取得独立的管理密钥，再填入页面密码框。不要把输出放进 Git、截图或公开文档。

   ```sh
   sudo cat /root/dpanel/compose/lan-center/data/failover/subscription-controller/local-source/admin-token
   ```

3. 每行粘贴一条节点链接，默认「追加节点（自动去重）」。先点「解析并校验」，确认协议、备注及去重数量，再点「保存并发布」。
4. 页面明确区分「已保存」「旁路由已读取并核验」与「待评估／健康检测结果」。语法校验通过不代表节点能连接外网，更不代表所有业务可用。
5. 在 OpenClash 的相应业务策略中选择现有的 `🔐 自定义节点`，再从这个全局入口选择新节点。添加节点本身不会切换业务出口。

这是**一个全局选择器**：同时选择它的多个业务，共用它当前选中的节点。默认选项为 REJECT；节点失败时不自动回落到公共节点、DIRECT 或其他业务出口。

节点名称使用「自建节点 · 备注 · 短标识」，标识由本地密钥与节点内容生成。面板不会返回节点密码或原始链接。

## 支持范围

本地解析 SS（SIP002 与传统整体 Base64）、VMess JSON 分享链接、VLESS、Trojan、Hysteria2、SOCKS5、HTTP(S)。VLESS 支持受支持的 TCP、WS、gRPC 与 Reality 参数；以本机实际 Mihomo 内核校验结果为准。

不识别的参数、插件、传输方式或缺失凭据会明确拒绝，不能通过忽略参数来强行导入。一次最多 100 个节点、约 192 KiB 输入。不会把链接发往公网转换站。URI 解析采用 [Shadowsocks SIP002](https://shadowsocks.org/doc/sip002.html)、[XTLS 分享规范入口](https://xtls.github.io/development/protocols/vless.html)、[Hysteria 2 URI 规范](https://v2.hysteria.network/docs/developers/URI-Scheme/) 的可表示子集。

健康检测沿用现有隔离入口和 SQLite 数据库。发布后触发重新发现，调度器在当前探测结束后的下一轮处理，不并发抢占生产业务选择器。`cooling` 表示故障冷却；`business-limited` 表示部分业务受限；过期结果不会显示成新鲜可用。

## 编辑、删除与空订阅

- 「编辑」：粘贴该节点新的完整链接；不会在网页回显旧密码。
- 「删除」：只移除对应的本地节点。
- 「替换全部」：用本次输入替换本地节点列表，允许留空，需要页面确认。
- 编辑或删除当前正在使用的自建节点，先将全局自定义入口设为 REJECT，回读确认，再关闭经过该入口的连接。其他出口的连接不在清理范围内。
- 发布失败保留上一个已提交版本；崩溃后的待完成事务仅恢复本地 provider。版本冲突会要求刷新，繁忙会明确拒绝，不能误报成功。
- 空来源在 provider 内保留一个阻断占位，避免内核不接受空 provider；它不出现在自定义入口和隔离检测入口，不算可评估节点。

## 发布链路与持久化

```text
3103 管理页
  → 本地解析、去重、输入限制
  → 与旁路由相同二进制的 Mihomo -t 校验（无监听、无外网请求）
  → 自建来源独立不可变版本、待提交日志
  → Local_Custom provider 刷新
  → 回读 provider + 自定义入口 + 隔离检测入口
  → 提交版本、触发节点发现
  → 现有隔离调度器探测、SQLite 记录
```

249 的唯一原始数据目录：

```text
/root/dpanel/compose/lan-center/data/failover/subscription-controller/local-source/
  state.json           已提交节点内容（含凭据）
  current.json         provider 当前发布指针
  pending.json         未完成事务日志，仅恢复期间存在
  releases/            至多保留 20 个版本
  receipt.json         最近发布结果
  runtime.json         最近的旁路由回读状态
  identity-key         本地身份去重密钥
  provider-token       旁路由拉取凭据
  admin-token          管理页密钥
```

原始目录与文件分别限制为 0700／0600。上述文件及密钥不进入 Git。SQLite 位于原有 `/data/node-capability.db`，不是另建一套健康数据库。

旁路由持久文件：

```text
/etc/openclash/custom/local-subscription-provider.yaml
/etc/openclash/custom/local-subscription-cache/provider.yaml
/etc/openclash/custom/strict-custom-policy.json
/etc/openclash/custom/jydn_strict_custom.rb
```

provider 拉取使用独立的 Authorization 请求头，管理链路指定 DIRECT；凭据不出现在 URL。自建节点仅进入现有全局自定义入口及隔离探测入口，公共池通过命名空间过滤排除它们。最后一个覆写钩子会重建这条关联，重启和订阅生成不会依赖人工修改缓存。

249 的运行扩展保存在 `/opt/lan-center-local-subscription/releases/`，Compose 增加三处代码挂载以便容器重建后保留。此次部署没有重建容器，当前进程与声明的持久挂载使用相同代码；仍需在未来正常维护时再次验收真正的容器重建。

## 本次备份与手动回退

2026-10-26 的旁路由备份：

```text
/root/openclash-backups/local-source-20261026-1792992187
```

249 的配置、原代码、订阅文件与在线 SQLite 备份：

```text
/var/backups/local-source-20261026-1792992179875585564
```

在确需回退、且本次部署后没有另外改动相关配置时，依次执行：

1. 在 **254 的 root SSH** 中恢复路由关联与原配置：

   ```sh
   ruby /root/openclash-backups/local-source-20261026-1792992187/stage/strict_custom_router_recovery.rb rollback /root/openclash-backups/local-source-20261026-1792992187
   ```

2. 在 **249 的 SSH** 中恢复原订阅管理与检测子进程代码：

   ```sh
   sudo python3 /var/backups/local-source-20261026-1792992179875585564/server_extension.py rollback --backup /var/backups/local-source-20261026-1792992179875585564
   ```

回退保留已添加的原始自建订阅数据，以便后续恢复，不把旧数据库覆盖到正在运行的生产库。脚本会检查设备身份、备份校验和、容器身份及配置差异。新增了业务私有绑定、另有配置修改，或容器后来已重建时，应先核对差异；不能绕过拒绝检查强行覆盖。

旁路由回退优先热加载，热加载失败才可能重启 OpenClash，会打断代理连接。249 的回退只重启订阅管理和节点检测子进程，保留 Kuma、CoreDNS 与容器本身。

上线期间的两端超时保护已在验收后解除；手动恢复脚本仍保留。已验证备份完整性、恢复脚本预检查与隔离故障恢复，没有为了演练而在生产环境再次执行整套回退。

## 验收边界

已在隔离环境用同版内核验证 HTTP 实际经过导入节点、节点故障时断流、其他业务继续访问、节点删除、内核重启、健康入库、认证和 CSRF；线上则用临时断路节点验证实际发布、自动发现、故障入库与移除。

用户尚未提供真实自建节点，因此真实供应商凭据、目标业务账号与地区可用性需在导入后继续观察。测试数据不能替代真实账号业务验收。

自动化单元测试：

```sh
python3 monitoring/lan-center/local-subscription/test_local_source.py
ruby scripts/test_strict_custom.rb
```

原始线上源码通过 `patch_runtime.py` 做窄范围扩展，保留已有准入、隐私出口和自动恢复逻辑；锚点变化时停止。`test_native_provider.py` 需要部署现场捕获的原始控制器、同版内核及其依赖，应在无生产卷的隔离容器里执行，不能直接当作生产启动脚本。
