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

- 生成配置共 121 个策略/节点组；其中 43 个自动节点池以 `url-test` 生成：36 个国家组、5 个实用/其他组以及全局自动和稳定自动；覆写模块在 Smart 内核上将它们统一转换为 `smart`，按目标站点分别学习和切换节点。
- Zashboard 的国家节点组统一使用中文名称，并提供亚洲、欧洲、美洲、中东非洲和大洋洲五个上层导航组；应用策略组使用“中文功能名（品牌名）”，兼顾可读性和品牌识别。
- 国家及线路叶子组使用 `REJECT` 作为空组安全兜底；`🧭 手动选择` 使用 `🛟 稳定自动` 作为可用性兜底。所有全局节点池都会过滤流量、到期、官网和订阅刷新提示。
- 节点国家校验优先让真实流量逐节点经过 `country.is`、`ipwho.is`、`IP.SB`、`countries.dev` 和 Cloudflare：只有成功来源中的严格多数、且至少两个来源返回相同 ISO 国家代码才采用在线结果；无法形成多数时才按国旗、国家、城市或代码名称降级判断。
- 所有 Smart 组使用 Cloudflare HTTPS 探测地址，测试间隔 120 秒、容差 `100 ms`、超时 5 秒、失败阈值 `2`，并要求 HTTP 状态 `204`。
- `🛟 稳定自动` 优选日本/新加坡 CUCM、专线流媒体线路，并以 `♻️ 自动选择` 作为非直连兜底。
- 海外功能父组默认通过 `🔒 隐私代理` 出站；品牌子组默认继承父组，并保留按国家或节点单独改路由的入口。`🔒 隐私代理` 只指向 `🛟 稳定自动`。
- `GEOSITE,geolocation-!cn` 位于 `GEOSITE,cn` 前，国内域名和 IP 最终由 `GEOSITE,cn` / `GEOIP,cn` 直连。
- `🏠 本地网络` 用精确域名、域名后缀、`IP-CIDR` / `IP-CIDR6` 和 private GEO 双重保护局域网，默认直连。
- `🌐 联网检测` 使用 classical `RULE-SET`，组合 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`DOMAIN-REGEX` 和 NTP 端口逻辑，降低系统误报断网的概率。
- Telegram、Netflix、Google、Apple 和 Meta 增加了选择性 `IP-ASN` 兜底；不对 Cloudflare 这类大量共享托管网络做宽泛 ASN 强制分流。
- 银行、政务、国内证券、国内网盘、国内音乐和游戏下载拥有独立策略组，默认 `DIRECT`，遇到线路异常时可单独切换到隐私代理。
- `GEOSITE,gfw` 强制进入 `🔒 隐私代理`；通用境外应用、`🌐 默认策略`、`🐟 漏网之鱼` 逐层收口到 `🛟 稳定自动`，防止历史地区节点或 DIRECT 选择绕过稳定链路。
- DNS 模块强制替换旧 `dns` 块，境外 DNS 经 `🔒 隐私代理` 查询，DIRECT 域名使用境内 DoH。
- TUN 同时接管 TCP/UDP，劫持 UDP 53 与 TCP 53，开启 `strict-route`，默认关闭 IPv6 和中国 IP 内核外旁路。
- `🛡️ 实时通信（WebRTC）` 默认 `REJECT`；其 classical 规则只针对 `10.88.0.0/24` 客户端，排除路由器 `10.88.0.254`，并用 `AND/OR/NOT + SRC-IP-CIDR + NETWORK + DST-PORT` 分别限定 UDP STUN/TURN 和 TCP 5349。
- 海外支付和数字货币默认继承 `🧭 手动选择`；该组未手选节点时由稳定自动兜底，手选后可保持固定出口。
- `🚫 广告拦截` 默认 `REJECT`，也可以在面板临时切换为直连或隐私代理。

## 实用精细版策略层级

规则按“具体品牌 → 功能分类 → 国内/海外兜底”的顺序匹配：

- AI：对话助手（ChatGPT）→ 人工智能 → 隐私代理。
- 通讯：Telegram、Discord、WhatsApp、Signal、LINE → 即时通讯 → 隐私代理。
- 社交：Instagram、X、Facebook、Reddit → 社交平台 → 隐私代理。
- 影音：YouTube、Netflix、TikTok、Disney+、HBO、Prime Video、Twitch、Spotify → 海外影音 → 隐私代理。
- 开发：GitHub、GitLab、Docker、NPM → 开发服务 → 隐私代理；PyPI、Linux 软件源和镜像站由 `rules/development.yaml` 补齐。
- 游戏：Steam、Epic、Xbox、PlayStation、Nintendo → 游戏服务；游戏下载单独默认直连。
- 支付交易：PayPal、Wise → 海外支付；OKX、Binance、Bybit → 数字货币；默认进入手选节点。
- 云服务：Notion、Apple、Google、Cloudflare、Microsoft、OneDrive、Dropbox 分别保留独立策略。
- 国内服务：国内银行、政务服务、国内证券、国内网盘、国内音乐默认直连。

## 多维规则分层

节点组只负责“可以选哪些节点”，策略组负责“业务默认走哪里”，规则负责“流量如何命中”。三者不互相混合：

1. 本地层：`DOMAIN` / `DOMAIN-SUFFIX` + `IP-CIDR` / `IP-CIDR6` + private `GEOSITE/GEOIP` → `🏠 本地网络`。
2. 条件层：`SRC-IP-CIDR` + `NETWORK` + `DST-PORT/SRC-PORT` + `AND/OR/NOT` → WebRTC 或联网检测组。
3. 精确业务层：自建 `clash-domain` / `clash-classic` `RULE-SET` → 银行、政务、网盘、节点校验等独立组。
4. 应用层：品牌 `GEOSITE` → 功能父组 → 节点策略。
5. IP 兜底层：只对归属边界明确的自有网络使用 `IP-ASN`，已有可靠分类时再用 `GEOIP`。
6. 国别层：`GEOSITE,geolocation-!cn` → 隐私代理；`GEOSITE,cn` / `GEOIP,cn` → 直连。
7. 终止层：`FINAL` 在生成 Mihomo 配置时对应 `MATCH`，只能位于最后。

`IN-NAME` / `IN-TYPE` 和 `SUB-RULE` 没有盲目加入默认模板：OpenClash 运行模式会改变入站，且传统 subconverter 对 `SUB-RULE` 存在参数错位的已知问题。仓库提供了默认不会命中真实流量的 [`modules/openclash-source-inbound-subrule.example.yaml`](modules/openclash-source-inbound-subrule.example.yaml)；只有在爱快固定设备 IP，并从 OpenClash 运行 YAML 确认真实入站名称后，才应复制、替换占位值并启用。

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
插件级开关请按文档在 LuCI 保存；模块刻意不含 `[General]`，以兼容当前版本的匿名 UCI 覆写处理。

### 3. alpha-smart 与最低延迟

- **插件设置 → 版本更新 → Smart 内核**：启用。
- **覆写设置 → Smart 设置 → Smart 策略自动切换**：启用；43 个 `url-test` 节点池会在运行时转换为 Smart。未选中的组保持懒检测，避免全量国家组同时测速。
- 启用 LightGBM 和模型自动更新，更新间隔设为 72 小时；关闭训练数据采集，避免生成 100 MB CSV 和持续磁盘写入。
- **Policy Priority** 设为 `0`（不加权），避免地区名称权重长期压过实际延迟和可用性；关闭 Prefer-ASN，减少首次访问前的强制解析。
- Smart 容差设为 `100 ms`，保留 120 秒健康检查、5 秒超时、失败阈值 `2` 和 HTTP `204` 校验。Smart 还会依据真实目标的连接失败记录重新选路，不只依赖单一测速 URL。

## 仓库结构与生成方式

```text
custom/groups.ini                       自定义策略组
custom/rules.ini                        自定义规则引用
docs/openclash-v0.47.156-settings.md    LuCI 逐按钮设置
docs/istoreos-openclash-one-arm-router.md  iStoreOS 独臂旁路由设置
modules/openclash-dns-privacy-override.yaml
modules/openclash-source-inbound-subrule.example.yaml  设备/入站/SUB-RULE 安全模板（默认不命中）
rules/*.yaml                            自维护 domain/classical 规则提供者
scripts/build.py                        生成最终模板
scripts/validate.py                     一致性检查
scripts/verify_node_geo.rb              多源在线出口国家校验（在 OpenWrt 运行）
upstream/metafenliu.ini                 基础模板（唯一基础来源）
metafenliu.ini                          自动生成结果，不要手改
```

原先构建脚本依赖的外部 `clashmetadingyue` 仓库已经不可访问。现在构建完全使用本仓库的 `upstream/metafenliu.ini`，不会因外部基础模板消失而中断。

修改 `upstream/`、`custom/` 或 `scripts/` 后，GitHub Actions 会重新生成并验证 `metafenliu.ini`。本地也可以运行：

```bash
python3 scripts/build.py
python3 scripts/validate.py
```

### 在线核对节点真实出口国家

静态模板只能按节点名称生成国家组，不能从订阅转换阶段直接获知每个节点的真实出口 IP。配置应用后，可在路由器上运行：

```bash
ruby scripts/verify_node_geo.rb --output=/tmp/node-geo-report.yaml
```

脚本通过 Mihomo API 逐个切换 `🔬 节点归属校验`，并让五个查询站点的请求经当前待测节点发出。它要求成功来源中的严格多数且至少两票一致；无法形成多数才使用模板中的名称正则。检测完毕会恢复该策略组原选择，不修改业务策略组。控制器密钥和代理端口认证会优先从环境变量读取、否则自动读取 OpenClash UCI，且不会被输出或写入报告；报告也不记录出口 IP。

如果在线国家和名称国家不同，结果标记 `ONLINE_NAME_MISMATCH`；如果在线识别出模板尚未定义的国家，标记 `UNMAPPED_ONLINE_COUNTRY`。这两类结果都以非零退出码结束，必须人工确认后再调整国家组，不能自动相信节点名称。

先做无网络自检：

```bash
ruby scripts/verify_node_geo.rb --self-test
```

## 新增一个应用

例如新增 `Pinterest`。

在 `custom/rules.ini` 添加：

```ini
ruleset=📌 图片收藏（Pinterest）,[]GEOSITE,pinterest
```

在 `custom/groups.ini` 添加同名策略组：

```ini
custom_proxy_group=📌 图片收藏（Pinterest）`select`[]💬 社交平台`[]🔒 隐私代理`[]🧭 手动选择
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

- `🌍 境外网站`：`rules/mygw.yaml` 中需要强制代理的域名。
- `🇸🇬 指定新加坡`：Massive、富途/moomoo、IBKR 常用域名，默认新加坡组。
- `💻 开发服务`：Python、Docker、Linux 软件源、Node.js、Go、Rust、Java、Conda 与开发工具下载域名。
- `🏦 国内银行`、`🏛️ 政务服务`、`📈 国内证券`、`☁️ 国内网盘`、`🎵 国内音乐`：各自规则文件负责精确命中，默认直连。
- `DIRECT`：运营商、局域网、NTP 及个人维护的其他直连例外；作为分类规则之后的补充。

国内直连的主体是基础模板中的 `GEOSITE,cn` 和 `GEOIP,cn`。`rules/direct.yaml` 只补充无法稳定归类或需要强制直连的例外，不应复制整套中国域名数据库。

## 推荐原则

- 更具体的应用和个人规则放前面，`GEOSITE,cn` / `GEOIP,cn` 放在海外分类之后、最终兜底之前。
- 海外功能父组默认不直连；Apple、Microsoft 延续直连优先，其余品牌只把 `DIRECT` 作为人工故障切换选项。
- 金融、交易平台优先固定地区和固定节点，不要跟随频繁切换的全局最低延迟组。
- 自动组默认使用 `10 ms` 容差兼顾响应速度与切换频率；追求严格最低延迟才使用 `0 ms`。
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
