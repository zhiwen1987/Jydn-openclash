# OpenClash v0.47.156 逐按钮设置

适用环境：OpenClash v0.47.156、alpha-smart 内核、`metafenliu.ini` 自定义转换模板。操作前先在顶部 **当前配置** 确认选中实际运行的订阅配置。

## 1. 配置订阅与转换服务

1. 打开 **服务 → OpenClash → 配置订阅**。
2. 点击 **添加**，填写配置名称和机场原始 **订阅地址**。
3. 开启 **在线订阅转换**。
4. **订阅转换服务地址**：选择 `https://api.asailor.org/sub`；不可用时选择 `https://api.wcc.best/sub`。
5. **模板名称**：选择 **自定义模板**。
6. **自定义模板 URL**：填写：

   ```text
   https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/metafenliu.ini
   ```

7. **UDP**：开启。其余重命名、排序、节点类型等选项按需要设置。
8. 保存并更新订阅，再从顶部 **当前配置** 切换到新配置。

第三方转换服务能够看到原始订阅地址。需要更高隐私时应使用自建 subconverter，并把 **订阅转换服务地址** 改为自己的 `/sub` 端点。

## 2. 安装 DNS/隐私覆写模块

1. 点击顶部 **运行状态**。
2. 在运行状态页点击 **覆写模块**。
3. 点击 **新增**（部分主题显示为 **+** 或 **添加模块**）。
4. 模块名称填写 `dns-privacy`。
5. 打开 `modules/openclash-dns-privacy-override.yaml`，从 `[General]` 复制到最后一行，粘贴到模块编辑框。
6. 若页面提供 **应用配置/指定配置文件**，选择当前实际运行的配置；不指定通常代表对全部配置生效。
7. 点击 **保存**，打开模块的 **启用** 开关。
8. 回到 **运行状态**，点击 **重启 OpenClash**。

模块使用 `<dns>!:` 强制替换原有完整 `dns` 值，不会与订阅生成的 DNS 合并。

## 3. 关闭冲突的 DNS 界面覆写

1. 点击 **覆写设置 → DNS 设置**。
2. 关闭 **自定义 DNS 设置 / Custom DNS Setting**。
3. 关闭 **追加上游 DNS / Append Upstream DNS**。
4. 关闭 **追加默认 DNS / Append Default DNS**。
5. 点击页面底部 **应用设置**。

不要在该页面再次粘贴完整 `dns:`；本方案已经由覆写模块独占生成 DNS。

## 4. TCP、UDP 与 DNS 53 接管

1. 点击 **插件设置 → 运行模式**。
2. **运行模式选择 / Select Mode**：选择 `fake-ip-mix (tun mix mode)`。
3. **网络栈类型 / Select Stack Type**：先选 `System`；若 UDP、Docker 或虚拟机异常，再测试 `Mixed`。
4. **代理模式 / Proxy Mode**：选择 **规则模式 / Rule Proxy Mode**。
5. 点击 **插件设置 → DNS 设置**。
6. **本地 DNS 劫持 / Redirect Local DNS Setting**：选择 **防火墙转发 / Firewall Redirect**。
7. 点击 **应用设置**。

`fake-ip-mix` 的 TUN 会接管 TCP 和 UDP。模块中的 `any:53` 与 `tcp://any:53` 分别劫持 UDP 53 和 TCP 53。

## 5. strict-route

v0.47.156 的插件设置页没有单独的 `strict-route` 按钮。模块已经加入：

```yaml
tun:
  strict-route: true
```

它会让连接遵循更严格的 TUN 路由，降低地址和 DNS 泄漏风险。若启用后局域网设备、Docker、虚拟机或旁路网关无法通信，进入 **运行状态 → 覆写模块 → dns-privacy → 编辑**，改为 `strict-route: false`，保存并重启后对比测试。

## 6. 关闭中国 IP 内核外旁路

1. 点击 **插件设置 → 流量控制**。
2. **路由本机代理 / Router-Self Proxy**：开启。
3. **常用端口代理模式 / Common Ports Proxy Mode**：选择 **禁用**。
4. **中国 IP 路由 / China IP Route**：选择 **禁用**，不要选择“绕过中国大陆”。
5. **本地 IPv4 网络绕过列表**：只保留自己的私网网段，不添加大陆公网 IP 段。
6. 点击 **应用设置**。

模块中的 `CHINA_IP_ROUTE = 0` 也会固定为禁用。国内连接会先进入 Mihomo，再由 `GEOSITE,cn` / `GEOIP,cn` 决定 `DIRECT`。

## 7. 关闭 IPv6，直到完整接管

### OpenClash

1. 打开 **插件设置 → IPv6 设置**。
2. 关闭 **代理 IPv6 流量 / Proxy IPv6 Traffic**。
3. 关闭 **IPv6 DNS 解析 / IPv6 DNS Resolve**。
4. **中国 IPv6 路由 / China IPv6 Route**：选择 **禁用**。
5. 点击 **应用设置**。

### OpenWrt WAN6

1. 打开 **网络 → 接口**。
2. 找到 `WAN6`，点击 **停止**。
3. 打开 `WAN6` 的 **编辑 → 高级设置**，取消开机自动启动/接口启动时自动连接。
4. 点击 **保存并应用**。

如果固件没有启动开关，可先只停止 WAN6，不要删除接口，便于恢复。

### LAN 的 RA/DHCPv6

1. 打开 **网络 → 接口 → LAN → 编辑 → DHCP 服务器 → IPv6 设置**。
2. **RA 服务**、**DHCPv6 服务**、**NDP 代理**全部设为 **禁用**。
3. 点击 **保存并应用**。

若固件使用服务器/混合/中继模式下拉框，三项均选择禁用。上游光猫或其他路由仍发送 RA 时，也必须在相应设备中关闭。

## 8. 最低延迟与 alpha-smart

1. 打开 **覆写设置 → Smart 设置**。
2. 关闭 **Smart 策略自动切换**。版本页的 **Smart 内核：启用**可以保留，两者不是同一个开关。
3. **Policy Priority（权重加成）**留空。该字段按正则/字符串匹配节点名称，不是填写策略组名称。
4. 点击 **应用设置**。

模板里的七个节点池均为 `url-test`，使用 HTTPS 探测地址、300 秒间隔和 `0 ms` 容差，因而按探测结果严格选择最低延迟节点。若网络波动导致频繁切换，可将容差调为 `30 ms`。

## 9. WebRTC 与浏览器独立 DNS

- `🛡️ WebRTC` 默认选择 `REJECT`，阻断常见 STUN/TURN 端口 3478-3481 和 5349；这可能影响网页会议和语音通话。
- 需要通话时把该组切换为 `🔒 隐私代理`，并确认所选节点支持 UDP。
- 浏览器关闭“安全 DNS”，Android 关闭“私人 DNS”，Apple 设备关闭 iCloud Private Relay 后再测试路由器 DNS 劫持。
- WebRTC 仍可经 443 或应用自定义端口工作；不能把端口阻断视为绝对防护，完整 TUN 接管和浏览器权限控制同样重要。

## 10. 验证清单

1. **运行日志**：没有 YAML 解析、策略组缺失、GEOSITE 不存在或规则下载错误。
2. **防火墙/调试信息**：DNS 重定向同时包含 `tcp, udp`，目标端口 `53`，重定向到 `7874`。
3. DNS 测试只显示预期解析路径；重复测试前清除浏览器和系统 DNS 缓存。
4. IPv6 测试不显示运营商 IPv6；若仍显示，继续排查光猫、旁路路由或其他 RA 服务器。
5. WebRTC 测试不显示中国公网地址；需要通话时再验证代理 UDP 是否工作。
6. 分别测试国内网站、海外网站、交易平台、流媒体和局域网访问，确认策略组命中符合预期。

无法仅靠 Clash/OpenClash 保证网站识别不出中国用户。网络层之外，账号地区、SIM/GPS、时区、语言、Cookie、支付资料和浏览器指纹仍可暴露地区。
