# 分流维护、自动数据试跑与恢复

这是 0.1.1 接管后的独立配置维护，不是内核或中心镜像升级。已发布的 0.1.1 离线 ZIP 没有重新打包，不包含本页新增的候选数据任务。

管理页面逐项操作见[完整页面手册](management-pages.zh-CN.md)。后续只读查明的订阅信息缺失、IPv6 检测出口及节点准入锁问题单列于[问题记录](diagnostics-20261027.md)，尚未实施的修复不计入本页已通过验收的配置维护。

## 已生效：稳定自动入口与系统总裁直连

- 69 个业务组及 6 个指定功能选择组均有 `🛟 稳定自动`：共 75 个，其中 72 个本次补齐；原首选、当前选择和节点池成员保持不变。
- 唯一自定义入口继续固定节点、失效断流；专用池和技术探测组不批量追加出口，避免循环或破坏控制器约束。
- `DOMAIN-SUFFIX,sysceo.com,DIRECT`、`DOMAIN-SUFFIX,drvceo.com,DIRECT` 位于规则顶部，并同步到转换模板及 direct 域名库。子域名一并匹配；不扩大为共享 CDN 全部直连。
- 当前为 103 个配置组 / API 104 组、144 条规则。75 是补齐入口的目标选择组数，不是节点数。

持久规则位于 `/etc/openclash/custom/jydn_routing_controls.json`；目标业务目录为 `jydn_stable_menu_catalog.json`。`openclash_custom_overwrite.sh` 在原覆写逻辑结束后调用 `jydn_routing_controls_hook.sh`，保证重新编译后入口仍在。修改这些文件必须先备份、用副本运行 `routing_controls.rb`、原生校验并检查选择状态，不能直接重启试错。

生产已备份至旁路由：

```text
/root/openclash-backups/shared-custom-20261026-1793033424
```

本次手动回退命令在旁路由 root SSH 内执行：

```sh
ruby /root/openclash-backups/shared-custom-20261026-1793033424/stage/recovery.rb rollback /root/openclash-backups/shared-custom-20261026-1793033424
```

恢复器核对设备、文件所有权、散列与业务选择；遇到后续修改应停止审阅，不能强制覆盖。已验收标记为同目录 `ROUTER_ACCEPTED`；限时恢复守护已解除。首次试运行未满足全部验收门槛并实际触发过回退，第二次重新备份后才完成验收。

安装器接管状态记录原本冻结文件散列。本次只对已核验的源/运行文件、覆写文件和保留的既有 GitHub 下载镜像设置建立审计新基线，记录前后散列并保留历史备份；没有改写原安装备份。GitHub 镜像选项在本次维护前已经不同，确认唯一 UCI 差异后保留现状。

## 候选数据库：定时更新，但尚未应用生产

生产原有 OpenClash 四库每日 05:00 更新保留。新增任务从 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat/releases/tag/latest) 收集 GeoSite、GeoIP DAT、Country MMDB、ASN MMDB，仅写独立候选目录，不修改生产库、DNS 或路由。

1. 每 6 小时执行，加入最多 10 分钟随机延迟；复用 `clash-center`，没有新增常驻容器。
2. 用 GitHub release SHA-256 校验；公开 API 无法访问时，改用同一发布者的配套 `.sha256sum`。后一种模式不伪造发布日期，字段为空。
3. 数据不变时核验本地散列后跳过重复下载、重复内核检查；单库变化只下载变化部分。失败保留上一候选。
4. 提取现有运行规则需要的分类，使用同一固定内核、无端口/无 DNS/无业务出口的样本做原生检查，分别验证 DAT / MMDB 模式。样本使用 `memconservative` 控制试跑内存；生产保留 `standard`，不能拿样本内存当作生产整图加载开销。
5. 下载总预算 360 秒、每路由最多 60 秒，限速 2 MiB/s；原生检查每次最多 60 秒、采样 RSS 上限 256 MiB，并检查容器内存余量。低优先级执行，只保留当前及两个旧候选。
6. 数据任务核心散列与生产原核一致；升级内核后会拒绝继续，必须重新验收再更新固定值，不能跳过版本限制。

这些限制减小影响，但容器内短时 CPU/内存仍共享。首次实际两次原生检查约 3.28 / 4.83 秒，采样峰值约 104 / 111 MiB；这是单次观测，不是长期资源保证。

主机任务：`clash-geodata-trial.service` / `clash-geodata-trial.timer`。样本定义见 [service](../monitoring/lan-center/geodata-trial.service) 与 [timer](../monitoring/lan-center/geodata-trial.timer)，容器名及挂载路径迁移时需要相应调整；没有加入 0.1.1 安装器的自动部署流程。

```text
249 主机：/root/dpanel/compose/lan-center/data/failover/geodata-trial/
容器内：/data/geodata-trial/
状态：state/status.json
候选元数据：state/candidate.json
不可变候选：state/candidates/<sha256>/
```

只读检查及本任务停止办法（249）：

```sh
sudo systemctl status clash-geodata-trial.timer --no-pager
sudo cat /root/dpanel/compose/lan-center/data/failover/geodata-trial/state/status.json
# 仅在需要取消本任务时执行；保留证据及候选，不影响原 OpenClash 更新
sudo systemctl disable --now clash-geodata-trial.timer
sudo systemctl stop clash-geodata-trial.service
```

这会停止后续调度。若容器内检查已经启动，不保证随 docker exec 客户端立即结束，工作进程仍受自身下载/检查预算约束；不要为此停止整个中心容器。

数据库试跑前，旁路由四库与控制文件备份在 `/root/clash-stack-backups/geodata-trial-1793030726`。目前生产库未替换，不需要为撤销候选任务恢复生产库。

首轮真实下载与 68 个 GeoSite 分类的原生兼容检查通过；随后经 systemd 再跑返回 `unchanged=true`，定时器 enabled、服务 Result=success。状态明确写 `production_applied=false`、`route_rehearsal=pending`。这不证明所有域名分类都正确，全面数据库切换仍需规则命中对比和业务灰度；没有据此自动全量上线。

## 网络验收与实际限制

- 两个系统总裁站点完成真实 TLS 握手，连接记录命中各自 DomainSuffix，完整 chains 为 DIRECT。
- 百度、Google robots、ERP、Grok 首页均 HTTP 200；三个管理页面均 200；DNS UDP/TCP 均有答案。
- 中心容器 ID、镜像及旁路由主内核 PID 保持原样，DNS/UCI 未改；当前业务选择未变。
- 静态菜单与幂等/防循环验证、候选任务 10 项单元测试通过。没有把页面成功等同于实际大文件下载、账号对话或长期稳定性。

如果驱动程序实际下载仍慢，需捕获下载时的目标域名、匹配规则、链路及吞吐，继续按证据增加明确域名。应用使用共享 CDN 或隐藏下载地址时，不能凭名称直接扩大直连范围。

## 内核更新：只读结论

核验时生产为 `alpha-smart-gdaf3ad0`，Smart 上游滚动发行资产为 `alpha-smart-4624551`，相对当前提交前进 8 个提交，资产更新于北京时间 2026-10-22 03:45。Release 的最早创建日期是 2025 年，不能拿它作为这次二进制更新时间。

[上游发行页](https://github.com/vernesong/mihomo/releases/tag/Prerelease-Alpha) · [精确代码差异](https://github.com/vernesong/mihomo/compare/daf3ad03021cca6031f4a7303ca6d861a14d5a16...462455136157a760937c666bba71afe33b1a809e)

差异包括低于 1ms 测速误报、dialer-proxy 循环校验开销、TLS 依赖修订和 TUN `dns-mode` 新选项等。配置样例说明 `dns-mode` 留空沿用旧行为，未发现要求重写现有分流组的迁移项；这属于代码审阅结论，不是新二进制兼容性验收。

生产尚未升级。实施前需要在隔离副本对新二进制做散列核验、原配置 `-t`、provider / Smart / DNS / TUN 路径及回退验收；同时更新安装器与候选任务的固定内核散列。不能直接替换内核后删除版本限制。
