# 进源 Clash Center 0.3 验收账本（2026-10-28）

## 1. 用途和结论边界

本文用于 GitHub 代码交接，记录截止 2026-10-28 的可复核验收状态。它不是生产上线完成证明，也不应将组件单测、容器 `healthy` 或一次 HTTP 200 改写成端到端通过。

状态分为四类：

| 状态 | 含义 |
|---|---|
| 组件测试通过 | 源码、fixture、事务及故障分支已在指定环境执行 |
| 真实协议通过 | 使用真实 CoreDNS/Kuma/Mihomo 协议或子进程，不是单纯 mock |
| 最终镜像未验收 | 源码通过不等于最终唯一 image hash 已通过 HTTP、浏览器、重启和回退验收 |
| 生产未部署 | 本账本创建时未据此文执行 249/OpenClash/DNS 生产切换 |

当前总结：核心功能源码和多数真实协议门槛已通过；最终唯一镜像仍需完整隔离验收，生产仍是“未部署”。

## 2. 已通过的组件测试

| 范围 | 命令/证据 | 结果 | 主要覆盖 |
|---|---|---:|---|
| Installer 全量 | `python -m unittest discover -s installer/tests -p 'test_*.py' -q` | 119 通过，1 跳过 | 部署、备份、回退守卫、镜像源策略、订阅生命周期、资源限制 |
| Unified Center 全量 | `python -m unittest discover -s monitoring/lan-center/unified-center -p 'test_*.py' -q` | 90 通过，1 跳过 | 统一会话/CSRF、操作队列、revision/CAS、DNS、Kuma、订阅 CRUD、异步缓存 |
| 验收工具 | `python -m unittest -q monitoring.lan-center.acceptance.test_isolated_lab monitoring.lan-center.acceptance.test_acceptance` | 17/17 | 候选隔离、私密字段、性能回归、Kuma 3101 不公开、隔离容器安全销毁 |
| 订阅生命周期扩展 | `python -m unittest -v monitoring.lan-center.unified-center.test_subscription_lifecycle` | 8/8 | N 来源、增删停用、URL 脱敏、Candidate 不暴露、heartbeat 不扰动 CRUD revision |
| Kuma 桥 | `node monitoring/lan-center/unified-center/test_kuma_bridge.js` | 3 suites 通过，48 个断言点 | 2.5.6 协议签名、CRUD、延迟读回、断线/超时、URL 脱敏与明确清空 |
| OpenClash 受管路由事务 | `ruby installer/tests/test_managed_sources_router.rb` | 20 tests / 163 assertions | `Managed_Auto` 精确接入 13 个消费组、Candidate 拒绝、CAS、Guard、回退与选择保护 |

说明：`local-subscription` 依赖 Linux `fcntl`。直接在 Windows 上运行其 discover 不是有效验收环境；已有 RC 的 Linux 镜像分段证据显示 50 项通过，但仍需在最终唯一镜像上重跑，不可直接继承为最终结论。

## 3. 已通过的真实协议证据

### 3.1 CoreDNS

- 已在 Linux 容器中显式启用真实集成门槛，临时 CoreDNS 真实启动、`ready`、UDP/TCP 查询及子进程清理共 5/5 通过，耗时 1.819 s。
- 私有脱敏证据文件名：`integrated-control-1793135265/real-dns-validator.json`。交接文档不收录原始响应。
- 首次 `EPERM` 已准确分类为 `coredns_execution_denied`；使用 `cap-drop ALL + NET_BIND_SERVICE` 后通过，不是“二进制缺失”。
- 此证据的 NXDOMAIN baseline 与隔离镜像 `passive_control` fixture 不同。后者必须另行严格校验 UDP/TCP `NOERROR + A 192.0.2.1`，不得混成一份证明。

### 3.2 Kuma 2.5.6

- 已对官方 2.5.6 源一致的隔离副本执行真实 Socket.IO 协议。
- 覆盖 HTTP/Ping/Port/DNS/分组 5 类监控的创建、详情、暂停、恢复、删除，10 条 heartbeat 历史，以及 webhook 通知的 CRUD 和本地测试。
- 验收结束后原 22 个监控和 1 个通知的 ID/表指纹已恢复。最终生产验收不对这 22 个对象执行破坏性写操作。
- 脱敏证据：`integrated-control-1793135265/kuma-real-protocol-test.json`。

### 3.3 真实协议仍未覆盖的部分

- 最终唯一镜像的统一 HTTP 登录、CSRF、四模块 snapshot/job 和真实读回。
- 最终唯一镜像中的真实 Mihomo provider refresh、节点名/数量/身份一致和选择恢复。
- 最终唯一镜像的桌面/手机 Playwright 渲染、轮询不丢草稿、无 console/network 异常。
- DNS apply/rollback 实际镜像链、重启恢复与保护散列。

## 4. 最终镜像状态

### 4.1 已有但不等于最终验收

- 已生成不含生产数据/凭据的离线构建上下文，构建过程禁止网络、`docker commit` 和生产数据注入。
- 已有 RC 分段测试和隔离协议证据，但 RC 不是最终唯一候选镜像。
- 源码冻结后必须重新构建唯一 final artifact，保存 image ID/digest、rootfs lineage、构建上下文 hash 和验收回执。

### 4.2 最终镜像必跑命令

```bash
python3 monitoring/lan-center/acceptance/isolated_lab.py layout
python3 monitoring/lan-center/acceptance/isolated_lab.py prepare \
  --input /root/private/clash-center-lab-input \
  --output /root/private/clash-center-lab-bundle \
  --image sha256:<final-image-id>
python3 monitoring/lan-center/acceptance/isolated_lab.py boot \
  --bundle /root/private/clash-center-lab-bundle
python3 monitoring/lan-center/acceptance/isolated_lab.py verify \
  --bundle /root/private/clash-center-lab-bundle
python3 monitoring/lan-center/acceptance/isolated_lab.py destroy \
  --bundle /root/private/clash-center-lab-bundle --remove-network
```

工具的强制约束：Docker internal 网络、零 host published port、`0.7 CPU / 768 MiB / 192 PIDs`、control/Kuma 独立数据卷、Candidate 不进生产内核、只销毁带验收 scope label 的容器/网络。

浏览器必须额外完成 1478×1066 和 390×844 两个视口，遍历 `overview/routing/nodes/subscriptions/dns/monitors/diagnostics/backups/activity` 九路由；不能仅用 API 验收代替真实渲染与交互。

## 5. 第三家订阅 502 的状态和上线口径

用户已明确允许“功能先加载”，因此第三家当前外部 `502` 不再阻断统一管理功能本身上线，但必须同时满足：

- 第三家状态只能标记为“外部不可用/待恢复/未验收”，不得写成已解析、已检测、已发布或已加载。
- 失败不能移动当前 accepted pointer，不得影响原有来源、DNS、节点拉取地址或当前业务选择。
- 系统应按冷却/定时调度继续复测，不因一次 502 永久排除，也不频繁抖动。
- 外部恢复后必须重新获得五段脱敏证据：发现 → 解析 → 两次独立隔离检测 → `Managed_Auto` 发布 → Clash 名称/数量/身份加载一致。
- 在上述五段全部通过前，GitHub README、使用手册、验收页和发布说明均必须保留“第三家未验收”。

## 6. 生产部署状态

截止本账本生成时：

- 0.3 最终唯一镜像：**未完成最终全链验收**。
- 249 统一管理入口：**未据此候选切换生产**。
- Kuma 外部 3101 端口取消：**未据此候选执行生产改动**。
- DNS、原 provider URL、节点拉取地址和当前业务选择：**本账本撰写过程中未修改**。
- GitHub 代码上传/发布：由主任务在最终证据和文档一致性检查后统一执行，本文不冒充已推送。

## 7. 最终交接前必须补齐

1. 以源码冻结后的唯一构建上下文重建 final image，记录完整 image ID/digest。
2. 在 final image 上重跑 Installer、Unified Center、Linux local-subscription、Node Kuma bridge、CoreDNS 真实集成及两个 self-test。
3. 用 `isolated_lab.py` 完成真实镜像 boot/verify/destroy，保存无凭据报告。
4. 通过统一 HTTP 会话验收四模块、Kuma 22+1、Candidate 不暴露、订阅 validate 和性能基线。
5. 执行桌面/手机 Playwright 九路由、稳定 revision 表单、DNS 草稿和 Kuma 脱敏字段交互。
6. 对保护对象进行切换前后 hash/语义对比，确认 DNS、原 provider URL、当前业务选择和其他容器无非预期变化。
7. 证明备份、自动回退守卫和人工回退命令均可用，再进入生产切换。
8. 用户允许第三家 502 暂不阻断功能上线，但最终报告必须把其单独标为“外部待恢复/未验收”。

## 8. 相关文档

- `docs/acceptance/integrated-control-20261028.md`：完整验收矩阵和性能方法。
- `docs/design/integrated-control-contract.md`：统一后端和模块契约。
- `docs/unified-image-operations.zh-CN.md`：镜像构建、升级、回退和验收操作。
- `docs/system-guide.zh-CN.md`：系统使用与维护。

## 9. GitHub 首次快照 CI 发现

开发快照 e695c663 上传后，Installer/source-checks、verify、usage-checks 通过；unified-checks 未通过。失败发生在隔离验收工具 prepare 测试：对公开源码 acceptance.py 错误施加私有文件权限检查；Git checkout 的 Linux 常规 0644 与该检查不兼容。该缺陷正在修复，不能把本地通过直接当作 GitHub CI 通过。原记录见 [Actions 40612838901](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40612838901)。修复后的新提交/CI 结果应另行记录。
