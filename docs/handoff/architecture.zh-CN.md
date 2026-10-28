# 架构与源码导航

## 数据流

局域网终端 → 爱快下一跳 → 254 OpenClash/Mihomo → 域名/IP 规则 → 业务 Selector → 原有节点或指定自定义出口。

249 clash-center 包含统一 HTTP/UI、订阅发布、节点评估、CoreDNS 和 Kuma；中心通过认证接口协同路由器，不替换 OpenClash 主程序。

## 模块入口

| 模块 | 文件/目录 | 关键语义 |
|---|---|---|
| UI | monitoring/lan-center/unified-center/assets/ | 原生 HTML/JS/CSS；沿用进源 Logo；无新增框架 |
| HTTP | monitoring/lan-center/unified-center/unified_center.py | snapshot schema2、异步缓存、作业 API |
| 写事务 | monitoring/lan-center/unified-center/control_operations.py | 4 workers/12 slots、CAS、共享写锁 |
| Kuma | kuma_management.py、kuma_bridge.js（同目录） | 官方认证 Socket.IO；不通过 iframe 或第二次登录 |
| DNS | dns_management.py、dns_validator.py、dns_diagnostics.py | 草稿、验证、应用、确认、恢复；检测证据分层 |
| 来源状态 | unified-center/extensions/subscription_lifecycle.py | 每来源解析/候选/检测/发布/冷却/下次检测 |
| 来源协调 | installer/runtime/upstream/subscription-controller.py | N 来源、持久覆盖、删除 tombstone、源故障隔离 |
| 准入 | installer/runtime/upstream/admission_queue.py | 两次间隔成功才准入；3 次失败冷却 1 小时后重测 |
| 节点能力 | installer/runtime/upstream/node-capability.py | 延迟与业务可用性分开；不把单个 HTTP 403 当全局结论 |
| 本地节点 | monitoring/lan-center/local-subscription/ | 原生管理、解析、预览和发布；持久数据不随订阅覆盖 |
| 镜像构建 | installer/build_unified_image.py、Dockerfile.unified | 离线 BuildKit，源码在镜像，/data 不执行代码覆盖 |
| 部署恢复 | installer/agents/unified_center_deploy.py | 状态备份、超时外部守卫、镜像身份、接受/回退 |
| 路由器事务 | installer/agents/managed_sources_router.rb | Managed_Auto 受控加入 13 个普通消费者；保留选择 |
| 最终隔离工具 | monitoring/lan-center/acceptance/ | internal 网络、无宿主端口、标签保护、状态散列 |

## 订阅与节点判断

原两家 provider 的 ID/URL 不改。候选节点不进入生产 core/GLOBAL；私有 loopback Mihomo 检测通过后，仅已准入节点进入 Managed_Auto。每轮最多测 2 个节点并跨来源公平调度。状态恢复使用 candidate/previous/newer 三向 CAS，不覆盖更新状态。来源名称/用量不等于节点数据可用。

自定义入口全局共用，业务按需选择，未配置/失效阻断，不自动退回公共节点。Grok 专属稳定出口、支付固定出口和专用业务池不得被普通自动池扩散覆盖。

## DNS 和 Kuma

初始部署只迁移 DNS 挂载方式，Corefile 内容不变。验证器将所有 listener 隔离到随机 loopback 端口，启动真实 CoreDNS 检查 ready/UDP/TCP，未知语法拒绝。DNS 泄露浏览器测试必须由浏览器发请求；容器探测不能冒充终端泄露结果。FakeIP/CDN 差异不是污染证明。

Kuma 当前协议基线 2.5.6；支持 group/http/ping/port/dns 和 webhook。密码只经专用 bind 路径短暂处理，JWT 保存在服务端权限 600 文件。敏感 URL 整条隐藏，编辑其他字段时不能把脱敏占位写回实际 URL。

## 已知兼容问题

CoreDNS 二进制带 cap_net_bind_service；测试 cap-drop ALL 会导致 EPERM，需要仅加 NET_BIND_SERVICE。宿主机不保证有 PyYAML，准备隔离输入可在候选镜像内运行，勿为测试安装宿主依赖。Windows Ruby 4.0.7 测试不替代 OpenWrt Ruby 兼容验证。
