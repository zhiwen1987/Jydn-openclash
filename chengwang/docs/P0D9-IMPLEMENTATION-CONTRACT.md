# P0-d9 完整产品候选组合与正常 HTTPS 验收合同

日期：2026-10-22。当前为实施合同，**不是验收成功或上线证明**。承接 P0-d8 已验收代码 `ecb1a4e` 与文档 `1afda30`，所有历史结果保留各自提交/运行归属。

## 要交付的真实变化

1. 将原主服务组合逻辑抽为父模块 Go1.23 的 `internal/serverruntime`，原 `cmd/server` 保留薄入口及原测试名，默认配置、监听、认证和写门不变；关服生命周期按本阶段强化。父模块只依赖既有 imagetrust 契约，不 import Go1.25 的签名模块。
2. 已有 Go1.25.8 `image-trust-api` 通过显式 `-product-config`，把真实 trust backend 接入同一个完整产品 `api.New`。不通过 HTTP 反代转发身份、不注入假 backend，不复制一套产品服务器。原 `-config` 窄 allowlist 候选行为保留。
3. Factory 只能取得共享 Audit 与固定 tenant/site/environment，返回 backend/独立写门/worker 生命周期/Close；不能替换认证或修改整份 API options。control-plane 与 image-trust/storeID 各自固定 scope。Trust 构造及恢复先于任何 worker 和监听；共享 Audit 只由 runtime 关闭。
4. 完整候选强制 TLS、candidate 环境；私有严格 JSON 绑定 Addr、身份文件、TLS、租户/站点和已有 Audit。发布/Shadow operation 写入关闭，无 Mihomo 连接、设备执行或生产网络。原主服务不因为代码可组合而已被安装或升级。
5. 停止时先关 admission、取消请求和 worker，等待已受理 handler 与 worker 结束，再关 trust/operation/audit；不把 Serve 返回当作所有请求结束，不在活跃写入期间关闭库。真实阻塞/取消/退出测试证明顺序。

## 页面与传输边界

- 候选仍只预载 D8 Vite manifest 中 trust entry 可达资产；不因完整产品 API 组合而开放通用 FileServer、源码、配置或主 App demo。现有完整 App/全部企业 UI 不因此宣告完成。
- 使用预装 Chrome + Node CDP，原 HTTP 38 检查门保留，另增完整 runtime 的真实 HTTPS 门；不安装新的浏览器依赖。
- TLS 测试 CA 仅在本轮私有 HOME 的 NSS DB 导入；控制新旧 NSS 路径，不误以为 user-data-dir 可隔离用户信任。不得改宿主全局信任，不得用 ignore-certificate-errors、SPKI 例外或 CDP setIgnoreCertificateErrors。
- 实际可信证书正例完成既有 25 项签名定义/22 条 journal/44 条审计的 UI 全流程与完整产品读接口；不可信链、错 SAN、过期三个实际 TLS 负例必须被真正浏览器拒绝，不发 Bearer、不进入 HTTP handler。观察器只记真实请求计数，不替换响应。
- 页面身份、非空、无遮挡、控制台、截图、交互、桌面/移动、实际中文字体继续检查。工件不含私钥、令牌、配置、NSS DB 或 profile；清理要读回，不用进程意图替代退出事实。

## 自动验收和证据

- 父/子原 Go 版本、依赖、lockfile、全部已接受测试集合及真实 Distribution/Sigstore 链不变。新增数量从实际普通/race transcript 校准，不先猜计数；旧 2311/669 集合不得被删除或改名绕门。
- 三子代理分别负责共享 runtime、浏览器 TLS/NSS、fixture/CI；主代理负责完整候选组合与配置、集成、原始工件复核和最终归档。所有源修改经单一集成者提交开发分支，禁止 main 合并。
- Windows 本机不运行受缓存故障影响的 Go；Go 在隔离 Ubuntu ordinary/race/vet 执行，源码/模块/node_modules/测试字体只读、私有构建缓存、non-root、cap=0、NoNewPrivs、loopback-only。
- 前置检查必须实际确认 certutil/运行版本；缺失失败关闭，不自动 apt 安装或削弱证书校验。此前 runner 软件清单不能证明当前 run 已有工具。
- 功能/普通/race/真实 TLS/浏览器/清理/源码/依赖证据均需核对到实际提交。失败重试留记录；任何绿 CI 的截图不可读等问题也必须计失败并修正。

## 不在本阶段完成的事项

生产访问或变更、正式镜像构建/签名发布、IdP/SSO、完整企业功能、主 App 全页面 HTTPS、公共 CA/生产证书生命周期、浏览器全兼容矩阵、坏盘/坏 checkpoint 自愈、WORM/外部见证、分布式 HA、长期容量/浸泡及设备执行仍未完成。九项恢复 blocker 与 `authorization=BLOCKED` 不解除；不承诺免维护、零 bug 或任何可用率。

当前 Docker 构建因未固定基础镜像仍受门禁阻断；本阶段不得绕过该门把二进制测试解释为容器或生产验收。任何生产变更需另行明确授权、先备份并验证恢复。

候选配置/停止/恢复边界见 [完整产品候选操作说明](PRODUCT-CANDIDATE-OPERATOR-NOTES.md)。

## 技术依据

- [Chromium Linux 证书管理](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md)：NSS 的新旧 HOME 路径与根 CA 的 C,, 仅服务器信任标记。
- [Chrome Root Store FAQ](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md)：本地受管证书参与 TCP TLS 的正常验证，不等于关闭校验。
- [CDP Network.getCertificate](https://chromedevtools.github.io/devtools-protocol/tot/Network/#method-getCertificate)：取真实连接 DER 证书材料并与私有 fixture 的公开证书指纹对照。

官方文档只支持实现机制；实际 runner 是否有 certutil、浏览器是否信任、三个错误证书是否拒绝，仍必须由本轮执行结果证明。
