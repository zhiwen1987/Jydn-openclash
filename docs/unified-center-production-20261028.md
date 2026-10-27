# 进源Clash Center 0.2.0：生产切换、验收与恢复

时间均为北京时间（Asia/Shanghai）。2026-10-28 03:49:30 已接受本轮统一面板镜像切换；本记录区分技术验收、实际网络观察和仍存在的业务告警，不表示全部互联网业务正常。

## 1. 实际上线对象

| 项目 | 本轮结果 |
|---|---|
| 日常统一入口 | `http://10.88.0.249:3103/` |
| 品牌 | 进源Clash Center，使用用户提供的原 Logo |
| 容器 / Compose 服务 | `clash-center` / `center` |
| 镜像标签 | `jydn/clash-center:0.2.0` |
| 生产镜像身份 | `sha256:f6aca74281a21bbe5276bdcf247e37a90b7678a2471d868b7df4c91d08a3bb57` |
| 镜像运行源码提交 | `dd2bd9df1574323303a3699d6a21b5dab4c4dea8` |
| 固定基镜像 | `sha256:eb0271488325b6f8801f7eebcf36ecf363c82b8ed7a3a8f9145250239771a8f2` |
| 镜像大小 | 2,681,613,170 字节；相对既有大基镜像新增 2,726,718 字节，不把增量当成完整镜像大小 |
| 生产容器身份 | `88870aadddf76aab8d4d4f612fde9beb981cddb1c2ae652f4a64983baf3a8d31` |
| 部署状态目录 | `/opt/clash-center-ui`，与历史 `/opt/lan-center-unified` 分开 |
| 部署事务 | `1793129830767687354` |

只重建了目标 `center` 服务，没有执行 Compose `down`，没有升级旁路由内核、Kuma 主程序、宿主系统或其他业务容器。容器同时承载 DNS、Kuma 和中心页面，所以有一次短时中断。重建命令耗时 40.93 秒，**该时间不是对全网实际中断时长的测量**。

保留原 3101 Kuma 和 3102 能力页面作为兼容入口；3103 原订阅页面保留在同源 `/classic/subscriptions`。统一入口包含总览、业务分流、节点管理、订阅与同步、DNS、业务监控、备份与恢复、操作记录八页。完整操作见[管理页面手册](management-pages.zh-CN.md)。

## 2. 已完成的验收

| 验收范围 | 证据与结果 |
|---|---|
| Linux 回归 | 安装与恢复 67 项、统一后端与代理 33 项、原本地订阅 50 项，以及两项原有自检全部通过 |
| 部署专项 | 19 项包含 DPanel JSON Compose、SQLite 在线备份、镜像谱系、单服务修改、并发所有权保护、接受后人工回退；已计入上述 67 项 |
| 实际隔离镜像 HTTP | 9 组生命周期检查通过：公开读、未认证拒绝、登录、同源/CSRF、选择冲突与 no-op、单节点测试、备份下载完整性、Kuma/Socket.IO、原生页面与 LuCI fixture |
| 实际备份归档 | 隔离任务 202 → 完成 → 私密下载；归档清单、可读性和其中 SQLite 完整性通过；不是仅检查文件存在 |
| 实际隔离重启 | 数据副本重启后恢复 43 个节点记录、3 家信息来源、84 个业务选择和 144 条规则；原备份保留，旧内存管理会话失效 |
| 浏览器 | 使用现有 Playwright；Browser 插件不可用。1478×1066 桌面、390×844 手机尺寸逐页验证，无页面横向溢出；图像与原设计参考实际对照 |
| 交互和刷新 | 搜索、详情、失败登录清空密钥、真实 API 字段、订阅 `metrics`、过期能力、30 秒轮询保留 iframe/草稿/筛选；后台冲突不静默覆盖 |
| 静态资源更新 | 首页禁止缓存，JS/CSS/Logo URL 带内容指纹，避免新旧界面混用 |
| Kuma 集成 | 实际 2.5.6 页面渲染和 Socket.IO 双向帧通过；根作用域 worker 只注销自身，无 fetch/cache 接管，统一入口不提供 Kuma 离线 PWA |
| 生产认证 | 沿用原管理密钥，登录 Cookie Path=/、受保护页面、注销失效验证通过；未在生产提交业务选择 |
| 生产镜像 | 35 个运行源码文件 SHA 与构建清单一致，真实 RootFS 谱系核验通过 |
| 生产数据 | 4 份 SQLite 备份完整性通过；运行数据库完整；Kuma 9 类逻辑配置表前后指纹相同 |
| 来源和凭据 | 两份来源清单及管理/provider 凭据文件指纹保持；3 家信息来源与 2 家节点发布来源分开显示 |
| 路由器 | 7 份受保护文件字节不变；84 个业务选择、144 条规则不变；内核 PID 424 未重启 |
| DNS | Corefile SHA 不变；容器内及当前 Windows 设备向 249 发起的 UDP/TCP 查询通过；DNS 配置、Windows DNS/系统代理均未修改 |
| 其他业务 | 切换窗口内其他 41 个容器指纹不变（包括本轮临时验收/传输实例）；没有操作 Lucky、ESXi、爱快或其他业务配置 |

隔离环境使用生产数据的私密副本、内部 Docker 网络及本地 Mihomo/LuCI fixture。fixture 的 123ms 只验证 API 协作和单位，**不作为真实互联网节点性能证据**。隔离容器不能连生产 249:3103 或 254:9090。真实网络请求另在生产前后观察，不与 fixture 混算。

## 3. 真实网络观察及告警

生产前：国内页面 200、Google gstatic 检测端点 204、Grok 首页 200。生产后国内页面和 Grok 首页继续成功；Google 检测端点曾超时，随后三次恢复 204（约 0.226、2.466、0.391 秒）。另一次 Google 主站请求在代理 CONNECT 200 后发生 TLS 握手超时；同批 gstatic 和 Cloudflare 端点为 204。

这说明不能把一次低延迟或主页成功当成整项业务稳定，也不能断言已查清 Google 所有失败的根因。取证时 Google 经“谷歌服务 → 隐私代理 → 稳定业务出口 → 日本高速06”解析；自动组的实际叶子可以自行变化，84 个 Selector 的人工选择均保持。此次没有为消除告警而改 DNS、共享节点或业务选择。

还有一项应明确记录：原有发布控制器在重启后执行了启动调度，03:41 的候选因 `production_smoke_failed:google:0,github:0` 自动回退。此前备份中的最新稳定发布为 03:21 的 accepted 记录，运行侧已核对回到保持配置和选择的版本。**本轮没有把这次候选尝试算成新的节点发布成功，也不能把整个过程说成未发生任何自动发布尝试。** 控制器的 `degraded/rolled_back` 警告继续显示。

Claude 对应能力错误、Google 证据不足及部分 Kuma 子监控告警没有隐藏。总览汇总服务和业务问题，出现红色状态时应展开具体问题；不能仅因核心进程在线就改成全绿。

Kuma HTTP 存活、SQLite 可读和子监控 heartbeat 是独立证据。子监控失败不再被描述成 Kuma 进程停止。LuCI 未登录时，经统一入口和直接访问均返回相同的 403；其自身认证被保留，本轮未代用户完成 LuCI/Kuma 账号登录或执行高级配置变更。

## 4. 备份与恢复

生产完整私密备份：

```text
/opt/clash-center-ui/backups/1793129830767687354
```

包含旧 Compose 原始 JSON 字节、原容器环境与挂载、原安装器 state，以及 `/data` 和 `/app/data` 快照；SQLite 使用在线备份。目录 0700、文件 0600，不上传 GitHub。

旁路由只读基线和配置备份：

```text
/root/clash-stack-backups/unified-ui-production-1793129826
```

本轮切换前启用了独立于 SSH 连接的 600 秒 systemd 回退守卫，接受后已停止。人工回退命令在 249 上执行：

```sh
sudo /opt/clash-center-ui/rollback.sh
```

脚本调用 `/opt/clash-center-ui/deploy.py` 和已保存事务号的 `rollback-request.json`。先确认当前事务仍属于本次部署；工具会核对 Compose、容器、统一 state 和旧安装器 state 的所有权，发生人工修改、容器被替换、备份损坏或事务漂移时拒绝自动覆盖。

回退恢复旧镜像、Compose 和三处原代码挂载，只重建中心容器；仍会短暂影响同容器 DNS/Kuma/页面。它**保留当前运行数据**，不把旧数据库回灌覆盖新增历史。数据库损坏恢复是另一项需要停相关写入、校验和重新验收的操作，不能用复制整个旧目录代替。

已测试回退算法、备份损坏拒绝、并发修改拒绝与接受后人工回退；本轮没有在生产注入故障或反复回退/重建来制造验收结果。中心备份页面的归档范围小于上述部署完整快照，以每次 `included/omitted` 清单为准，不能代替路由器或整机备份。

旧安装器 state 的容器/镜像身份已同步。只读检查未发现已安装的 `clash-stack-watchdog` systemd 单元，因此**不声称长期外部 watchdog 已启用**；既有容器内 supervisor 和 Docker 重启策略保留。本轮临时发布回退守卫也不等于长期故障监控。

## 5. 交付与限制

- 使用：[系统手册](system-guide.zh-CN.md)、[页面操作](management-pages.zh-CN.md)。
- 构建、校验和恢复：[统一镜像操作手册](unified-image-operations.zh-CN.md)。
- 脱敏机器证据：[unified-center-20261028.json](evidence/unified-center-20261028.json)。
- 本轮镜像为 Linux amd64、既有审计站点的升级包；原 0.1.1 Windows 离线安装 ZIP 没有重打包，不把旧 ZIP 当作已含新 UI。
- 当前部署代理针对旧版三处受管代码 bind 的迁移；后续纯镜像到镜像更新必须重新做兼容检查，不能绕过拒绝条件强行执行。
- DNS 页当前只公开安全解析出的上游和 health/ready 等证据；监听、模式等没有返回的字段显示未知，不能把它当成完整 DNS 配置编辑器。
- 未验收所有账号登录、真实对话、支付、流媒体播放、每条路由、每个节点或长期可用率；单容器维护仍有共同中断边界，不承诺零故障或免维护。

## 6. 归档身份与下载

镜像归档已完成 OCI 内容寻址链、44 层内容和解压 DiffID 校验，并实际执行 `docker load` 往返，导入后的镜像身份仍为本记录中的 `f6aca742…`，生产容器没有因此重建。

```text
文件：Clash-Center-0.2.0-linux-amd64.tar.gz
大小：661018403 字节
SHA-256：cc7d19f68857b833feabfb3a5ed8c62ff94d4ad43ec27b92e039c650dbeffc37d
```

Docker/containerd 的 OCI manifest 身份与 config blob 摘要不同。此次归档根 manifest 为 `f6aca742…`，config 为 `ebd3cd06…`，不能把两者当成同一个散列；校验器分别验证根、配置、压缩层、解压层，以及 legacy manifest 的交叉引用，不通过放宽身份检查来绕过差异。参考 [Docker containerd image store](https://docs.docker.com/engine/storage/containerd/) 和 [containerd Content Flow](https://containerd.io/docs/2.4/content-flow/)。

上传完成后在 GitHub `v0.2.0-unified` 发行页提供归档、manifest、源码清单、SHA256SUMS、部署代理及操作手册。完整源码仍在仓库；归档和公开清单均不包含生产数据、订阅 Token、密码或私钥。公开[构建输入清单](evidence/unified-center-0.2.0-context.json)可用于核对运行源码。
