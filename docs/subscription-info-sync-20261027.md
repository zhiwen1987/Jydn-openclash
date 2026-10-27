# OpenClash“转换”到名称、用量的单向自动同步

2026-10-27 增量；在已有 `clash-center` 上接入，不增加容器，不更换 OpenClash 主程序。原 0.1.1 ZIP 未重建，不自动包含本次增量。

## 日常怎么用

在 OpenClash“编辑配置文件订阅信息”中，修改名称精确为 **转换** 的唯一条目的订阅地址，保存即可。249 约每 30 秒读取一次，新增、删除、重排会同步到独立信息清单；3103 和当前受管配置的用量卡片按这份清单显示。

只想保存地址、查看用量时，不需要点击节点更新、切换配置或重启 OpenClash。若主动点击原有节点更新按钮，属于插件原功能，可能更新其配置，并非本同步器的行为。

页面显示来源同步状态和最后成功时间。地址同步、用量采集、页面刷新是三种周期：约 30 秒、正常约 600 秒、约 30 秒。失败按来源分别退避，限流、网络故障和大量来源会延长等待，不承诺每个来源 30 秒取得新用量。

## 两份清单的边界

| 对象 | 用途 | 本次行为 |
|---|---|---|
| OpenClash `config_subscribe` 中“转换”的已保存地址 | 信息来源的上游 | 只读，不提交 UCI |
| `/data/subscription-usage/information-sources.json` | 名称和套餐信息 | 单向同步，最多 128 条，非固定两家/三家 |
| `/data/subscription-sources.json` | 节点获取、准入及发布 | 不写入，不因信息同步触发发布 |
| 当前 YAML provider URL、DNS、业务选择 | 生产转发 | 不修改、不切换 |

当前站点容器 `/data` 的实际宿主机路径为 `/root/dpanel/compose/lan-center/data/failover`。信息来源数不等于节点数，也不代表新增来源已经参与生产节点发布。

地址去掉不参与 HTTP 请求的 fragment 后去重；已有来源保持 ID 和缓存。新地址使用稳定散列 ID，改地址不冒用旧账户的名称/用量。手工信息条目不归同步器删除；同 URL 手工条目优先，`display_name` 可明确指定显示名。首次接入沿用原两家 ID，保留有效缓存。

仅采集上游明确提供的标题和 `subscription-userinfo`，不从 URL 猜机场名称或虚构用量。可选 `expire=` 空值只表示到期未提供，保留有效用量；不是永久有效。负数、非法必填字段、重复字段仍拒绝。

## 失败、空清单与恢复

- SSH 不通、地址格式无效、条目不存在/重名、存在未提交 UCI 修改：显示同步故障，保留上次清单，不能当作“用户删除了全部地址”。
- 明确保存空地址，或条目被停用：只清除同步器管理的条目，保留人工信息来源。不会删除节点发布来源。
- 清单损坏：运行中保留有效清单；订阅进程/隔离容器重启后，可读 `information-sources.good.json` 的有效副本，页面仍标记主清单异常。同步器拒绝覆盖损坏的人工文件，需核对可信备份后修复，避免把人工修改悄悄抹掉。
- 清单、good 或 `source-mode.json` 表明已启用独立模式后，不因清单丢失/为空退回节点发布清单。失去完整持久目录需要恢复备份，不自动猜配置。
- 同步状态超过 120 秒未更新显示超时；下一次有效同步恢复正常。单来源取数失败只影响该卡片。

## 实现与权限

249 使用宿主机专用 `clash-subscription-info-sync.timer` / `.service`，短周期 oneshot；不在常驻中心再开一个服务容器。agent、配置、私钥和固定主机公钥位于 `/opt/clash-stack/production/subscription-info-sync/`，仅 root 可读。

254 入口 `/etc/openclash/custom/subscription-info-exporter/export.lua` 只读取“转换”的地址。专用 ED25519 密钥在 249 生成，私钥不离开该主机。Dropbear 仅新增一条带 `restrict` 和固定 `command` 的授权，禁止终端和转发；入口额外校验来源为 249，且原命令必须是固定导出命令。原五条管理授权保持原样，SSH 和核心不重启。实现参考 [Dropbear 2024.86 授权选项](https://github.com/mkj/dropbear/blob/DROPBEAR_2024.86/src/svr-authpubkeyoptions.c)，实际另验收任意命令和转发均被拒绝。

相关代码位于 `monitoring/lan-center/subscription-usage/`：`source_export.lua`、`export.lua`、`source_sync.py`、`install_sync.py`、`deploy_exporter.rb`。部署工具限定当前站点路径，不是任意环境自动探测安装器。换网段、目录、插件或 Dropbear 版本须重新确认，不直接照搬生产凭据或绑定地址。

## 备份与回退

本次修改前备份：

- 254：`/root/clash-stack-backups/info-sync-1793114248/`，包含当前源/运行配置、UCI、DNS/网络/防火墙、核心、覆写、原 UI 和管理授权；文件散列核对通过。
- 249：`/var/backups/clash-usage-auto-1793114250/`，包含原发布清单、元数据代码/缓存、当前状态、Compose、在线 SQLite 备份；数据库完整性检查为 `ok`。
- 空可选到期兼容补丁：249 `/var/backups/clash-usage-auto-1793115352/`。
- 已接入版本的专用密钥、固定主机公钥、agent、配置和 unit 私有恢复副本：249 `/var/backups/clash-usage-auto-1793114250/runtime-recovery/`，7 个文件及散列清单，仅 root 可读。与修改前备份分开，不公开其中私钥。

备份包含敏感信息，只在设备受信 SSH 终端使用，不上传 GitHub。下面为**撤销本轮增量**的顺序，不会恢复整机或覆盖现有发布数据库；执行前核对是否发生后续人工修改。工具发现后续同文件改动会拒绝覆盖，应先审查，不能绕过保护。

249，以 root 执行：

```sh
python3 -B /var/backups/clash-usage-auto-1793114250/install_sync.py rollback /var/backups/clash-usage-auto-1793114250
python3 -B /var/backups/clash-usage-auto-1793115352/deploy_server.py rollback /var/backups/clash-usage-auto-1793115352
python3 -B /var/backups/clash-usage-auto-1793114250/deploy_server.py rollback /var/backups/clash-usage-auto-1793114250
```

254，以 root 执行：

```sh
ruby /root/clash-stack-backups/info-sync-1793114248/deploy_exporter.rb /root/clash-stack-backups/info-sync-1793114248/helpers.rb rollback /root/clash-stack-backups/info-sync-1793114248
```

先停专用 timer，再倒序恢复两次元数据代码，最后恢复路由器 UI 并撤销专用只读授权。保留信息文件和人工条目用于核查；旧采集代码忽略它们，重新读取原节点来源用于显示。不重启整个中心、DNS、Kuma 或 OpenClash 核心；元数据进程会短暂重载。不要手工恢复旧 `current.json` 或在线数据库来“回退页面”。

每次部署配有独立 20 分钟守卫，验收确认后停止自动回退。守卫不是长期灾备：恢复整个持久卷、丢失私钥或更换宿主机，应先核对恢复备份及主机公钥、只读授权，再恢复专用服务。不能把旧快照整机恢复当作最小影响回退。

## 验收范围

完整脱敏结果见[机器可读证据](evidence/subscription-info-sync-20261027.json)。隔离环境使用生产镜像、实际订阅启动入口、模拟 HTTP 来源、独立卷、无外部网络且无发布端口。覆盖增删、重排、人工条目、错误导出、单来源失败、实际容器重启、损坏清单恢复、空清单重启、重新添加、同步超时及恢复；空可选到期另有真实 HTTP 场景。

结果：最终完整重跑的 17 项新隔离场景、66 项 Python 自动回归和 9 项路由器 Lua 解析测试通过。生产 3 家名称和用量均取得，第三家空到期正确显示“未提供”；3103 实际页面与 LuCI 真实 HTTP 返回均确认 3 家。定时同步连续采样正常，节点发布记录数量和当前指针未变。

浏览器已检查桌面和窄屏用量卡片；卡片自身无横向溢出。3103 原有其他宽表格在窄屏仍可能撑宽整页，本次未重做页面布局。控制台原有未解锁管理接口返回 401、无 favicon 返回 404，与用量读取无关；未放宽认证来消除报错。

生产核对包括 3 条信息来源、原 2 家节点来源不变，真实受限 SSH、timer 连续更新、3103 与 LuCI 元数据、84 个业务选择、规则定义、配置文件、核心 PID、中心容器身份/启动时间和 DNS/Kuma 进程。生产未重启容器或宿主机；隔离恢复不能替代整机断电、磁盘损坏、丢失密钥或插件升级验收。上游未返回信息时不保证可采集，不承诺所有节点或业务的端到端可用率。
