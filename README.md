# Jydn OpenClash 自用分流模板

面向 OpenClash v0.47.156 与 alpha-smart 内核的自用配置模板。仓库生成最终的 `metafenliu.ini`，并提供 DNS 防污染、防泄漏覆写模块和对应的 LuCI 设置说明。

> 这套方案能降低公网出口、DNS 和常见 WebRTC 路径暴露中国网络位置的风险，但不能隐藏账号地区、SIM/GPS、时区、语言、Cookie 或浏览器指纹。

## 地址速查

| 用途 | 地址 |
| --- | --- |
| 自定义模板 URL | `https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/metafenliu.ini` |
| DNS/隐私覆写模块 | `https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/modules/openclash-dns-privacy-override.yaml` |
| OpenClash 默认转换服务 | `https://api.asailor.org/sub` |
| 备用转换服务 | `https://api.wcc.best/sub` |

在线转换服务会接触原始订阅地址，存在隐私风险。信任边界要求较高时，应自建 subconverter；不要把机场订阅地址、Token 或节点信息提交到本仓库。

## 主要功能

- `🇭🇰 HK`、`🇹🇼 TW`、`🇯🇵 JP`、`🇸🇬 SG`、`🇺🇸 US`、`🧊 冷门节点`、`♻️ 自动选择` 全部使用 `url-test`。
- 所有自动组使用 Cloudflare HTTPS 探测地址，测试间隔 300 秒，容差 `30 ms`，在低延迟与出口稳定性之间取平衡。
- 海外应用默认不提供 `DIRECT`，集中通过 `🔒 隐私代理`、地区组或手动节点出站；`🔒 隐私代理` 同时直接列出全部物理节点。
- `GEOSITE,geolocation-!cn` 位于 `GEOSITE,cn` 前，国内域名和 IP 最终由 `GEOSITE,cn` / `GEOIP,cn` 直连。
- DNS 模块强制替换旧 `dns` 块，境外 DNS 经 `🔒 隐私代理` 查询，DIRECT 域名使用境内 DoH。
- TUN 同时接管 TCP/UDP，劫持 UDP 53 与 TCP 53，开启 `strict-route`，默认关闭 IPv6 和中国 IP 内核外旁路。
- 常见 WebRTC STUN/TURN 端口默认 `REJECT`，需要网页通话时可临时切到 `🔒 隐私代理`。
- 交易平台保留独立策略组，建议手选固定节点，减少出口 IP 频繁变化。

## OpenClash v0.47.156 使用方法

### 1. 添加配置订阅

1. 打开 **服务 → OpenClash → 配置订阅**，点击 **添加**。
2. **订阅地址**：填写机场提供的原始订阅地址。
3. 开启 **在线订阅转换**。
4. **订阅转换服务地址**：选择 `https://api.asailor.org/sub`；不可用时再试 `https://api.wcc.best/sub`。
5. **模板名称**：选择 **自定义模板**。
6. **自定义模板 URL**：填写：

   ```text
   https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/metafenliu.ini
   ```

7. 建议开启 UDP；保存后更新订阅，并在右上角 **当前配置** 中切换到新配置。

### 2. 安装 DNS/隐私覆写

下载 [`modules/openclash-dns-privacy-override.yaml`](modules/openclash-dns-privacy-override.yaml)，按 [`docs/openclash-v0.47.156-settings.md`](docs/openclash-v0.47.156-settings.md) 的逐按钮说明安装。

如果 iStoreOS 只用一个 LAN 口作为旁路由，请先按 [`docs/istoreos-openclash-one-arm-router.md`](docs/istoreos-openclash-one-arm-router.md) 完成独臂拓扑、DHCP、网关、DNS 和防火墙设置。

模块使用 `<dns>!:` 强制替换完整 DNS 配置。不要同时在 **覆写设置 → DNS 设置** 中再生成另一套自定义 DNS。

### 3. alpha-smart 与最低延迟

- **插件设置 → 版本更新 → Smart 内核** 可以保持启用。
- **覆写设置 → Smart 设置 → Smart 策略自动切换** 必须关闭，否则 `url-test` / `load-balance` 组会被转换为 Smart 组。
- **Policy Priority（权重加成）** 留空。它匹配的是节点名称，不是 `🇭🇰 HK` 等策略组名称，也不参与本模板 `url-test` 的纯延迟排序。
- 模板默认使用 `30 ms` 容差减少出口频繁切换；如需严格追随当前最低延迟，可把 `upstream/metafenliu.ini` 中自动组末尾的 `30` 改为 `0` 后重新生成。

## 仓库结构与生成方式

```text
custom/groups.ini                       自定义策略组
custom/rules.ini                        自定义规则引用
docs/openclash-v0.47.156-settings.md    LuCI 逐按钮设置
docs/istoreos-openclash-one-arm-router.md  iStoreOS 独臂旁路由设置
modules/openclash-dns-privacy-override.yaml
rules/*.yaml                            自维护域名列表
scripts/build.py                        生成最终模板
scripts/validate.py                     一致性检查
upstream/metafenliu.ini                 基础模板（唯一基础来源）
metafenliu.ini                          自动生成结果，不要手改
```

原先构建脚本依赖的外部 `clashmetadingyue` 仓库已经不可访问。现在构建完全使用本仓库的 `upstream/metafenliu.ini`，不会因外部基础模板消失而中断。

修改 `upstream/`、`custom/` 或 `scripts/` 后，GitHub Actions 会重新生成并验证 `metafenliu.ini`。本地也可以运行：

```bash
python3 scripts/build.py
python3 scripts/validate.py
```

## 新增一个应用

例如新增 `Discord`。

在 `custom/rules.ini` 添加：

```ini
ruleset=Discord,[]GEOSITE,discord
```

在 `custom/groups.ini` 添加同名策略组：

```ini
custom_proxy_group=Discord`select`[]🔒 隐私代理`[]🇭🇰 HK`[]🇹🇼 TW`[]🇯🇵 JP`[]🇸🇬 SG`[]🇺🇸 US`[]🧊 冷门节点`[]🧭 手动选择
```

运行构建后提交。`ruleset=` 的目标名称必须和 `custom_proxy_group=` 名称完全一致，包括 emoji、空格与大小写。

## 新增自己的域名列表

在 `rules/` 新建文件，例如 `rules/mysite.yaml`：

```yaml
payload:
  - '+.example.com'
  - '+.example.net'
```

然后在 `custom/rules.ini` 添加：

```ini
ruleset=MySite,clash-domain:https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/rules/mysite.yaml,86400
```

并在 `custom/groups.ini` 添加同名 `MySite` 组。域名规则文件只放域名；IP/CIDR 应使用单独的 `clash-ipcidr` 或 `clash-classic` 文件。

## 当前已内置的自定义规则

- `走国外`：`rules/mygw.yaml` 中需要强制代理的域名。
- `访问新加坡`：Massive、富途/moomoo、IBKR 常用域名，默认新加坡组。
- `🧑‍💻 开发服务`：Python、Docker、Linux 软件源、Node.js、Go、Rust、Java、Conda 与开发工具下载域名。
- `DIRECT`：国内银行、政务、证券、网盘、音乐、运营商及个人维护的直连域名。

国内直连的主体是基础模板中的 `GEOSITE,cn` 和 `GEOIP,cn`。`rules/direct.yaml` 只补充无法稳定归类或需要强制直连的例外，不应复制整套中国域名数据库。

## 推荐原则

- 更具体的应用和个人规则放前面，`GEOSITE,cn` / `GEOIP,cn` 放在海外分类之后、最终兜底之前。
- 海外服务组默认不放 `DIRECT`；需要直连时先建立独立策略组观察。
- 金融、交易平台优先固定地区和固定节点，不要跟随频繁切换的全局最低延迟组。
- 自动组要稳定可用时，可使用 `30 ms` 容差；追求严格最低延迟才使用 `0 ms`。
- 不开启 OpenClash 的“绕过中国大陆 IP”，让所有连接先进入 Mihomo，再由规则决定 `DIRECT`。
- IPv6 未被 TUN/TProxy、DNS 和防火墙完整接管前保持关闭。
- 浏览器安全 DNS、Android 私人 DNS、iCloud Private Relay 等独立加密 DNS 通道应单独关闭或纳入接管测试。
- 每次修改后检查 OpenClash 运行日志，确认没有策略组缺失、GEOSITE 不存在、YAML 解析或规则下载错误。

## 参考

- [OpenClash 官方仓库](https://github.com/vernesong/OpenClash)
- [OpenClash 官方覆写模块参数与 YAML 操作符](https://github.com/vernesong/OpenClash/blob/master/luci-app-openclash/root/etc/openclash/overwrite/default)
- [OpenClash 官方订阅转换界面定义](https://github.com/vernesong/OpenClash/blob/master/luci-app-openclash/luasrc/model/cbi/openclash/config-subscribe-edit.lua)
- [Mihomo DNS 配置](https://wiki.metacubex.one/config/dns/)
- [Mihomo TUN 配置](https://wiki.metacubex.one/config/inbound/tun/)
- [subconverter 外部配置说明](https://github.com/tindy2013/subconverter#external-configuration-file)
