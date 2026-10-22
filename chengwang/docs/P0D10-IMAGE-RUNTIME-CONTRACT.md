# P0-d10 实际候选镜像与隔离运行合同

日期：2026-10-22。状态：实施中；本文不是镜像已构建、已批准或上线的证明。承接 P0-d9 代码 `875db6da`、归档 `0c2988f`；后者父回归 run `39801395231` 已 completed/success。

## 要交付的端到端变化

1. 在既有只读源码/模块缓存、断外网、非 root、cap=0、NoNewPrivs 的 Linux 编译环境，额外构建 Go1.25.8、CGO=0、linux/amd64 的真实 `image-trust-api`，不删改旧 CGO=1、普通/race、Registry 或浏览器检查。
2. 根据实际 ELF 头/动态依赖、Go buildinfo、Git revision、二进制 SHA256 和已接受 Vite 产物摘要建立白名单构建上下文。只打包真实入口与 trust entry 可达图（保留 `.vite/manifest.json`），不装入主 App demo、源码、工具链、测试程序、配置、私钥、身份或状态。
3. 独立 `deploy/product-candidate/Dockerfile` 使用 `FROM scratch`，没有外部基础文件系统、可变镜像 tag、远程 Dockerfile frontend 或安装器；入口直接执行镜像内程序，默认数字 UID/GID 10001，不提供默认私有配置。必须真实检查静态 ELF 并实际启动，不把 CGO=0 字面开关当作可运行证明。
4. 真实 Docker build/load，只按本轮本地 image ID 运行，不发布 Registry。image ID 是 config 身份，不是远端 manifest digest；源码、二进制、镜像内文件、实际 PID1 可执行文件与启动参数分别读回。打包/本地构建不是独立 builder attestation、SLSA 等级、签名发布或可重复构建证明。
5. 临时 UID/GID 10001 材料严格满足原有私有读取规则。四个实际镜像实例使用各自已有 Store/Audit、正常/不可信/错 SAN/过期证书；仅临时配置树只读挂载，trust/data 独立可写。镜像 `/app` 与程序不能被宿主 bind 替换。
6. 正例 `--network none`，其他证书反例显式共享它的网络命名空间；没有宿主端口、外部路由或接口、Docker socket、host PID、特权或生产路径。实际 inspect 和 `/proc` 核对只读根、非 root、cap=0、NoNewPrivs、CPU/内存/PID 限制及 restart=no。浏览器进入同一私有网络命名空间，以正常私有 NSS 信任完成既有 HTTPS45检查及真实父产品 API 读取。
7. 真入口不增加调试/测试 HTTP 接口。错误证书的客户端拒绝、零 HTTP 响应/Bearer 由真实浏览器证明；不能借旧进程内测试观察器声称镜像内 handler 计数为零。签名惰性测试定义仍非生产批准材料。
8. 向实际 PID1 发 SIGTERM，确认退出码0而非超时强杀，然后独立重开四个 Store/Audit 检查序列、generation、journal22/audit44、ACK 与账本不变。正例按同一 image ID/状态再次启动、实际 TLS/API 读回、正常停止再核对。
9. 缺 checkpoint、缺 TLS 私钥、错误权限、未知配置字段分别在真正镜像入口失败关闭；恢复精确的本轮输入后再验证状态。禁止为换绿放宽权限/签名/TLS/时效检查、删库重建或回收 grant。
10. 所有创建对象以本轮 UUID/标签/精确 ID 追踪，清理只限本轮容器、镜像、私有材料与已验证退出的浏览器 profile；无全局 prune。工件只含安全投影、摘要、日志、浏览器报告/截图，不上传 ready、身份、原始 inspect、配置、私钥、NSS/profile 或含材料的状态目录。

## 验收与不变条件

- 必须针对提交的实际源码执行，再读回原始 transcript/工件。旧父2320、子700和所有更早完整集合保持；新增带 `productimage` tag 的 fixture 单独运行，不拿无环境分支或合成报告充作真实镜像证明。
- 镜像检查器必须有拒绝负例；真实镜像启动/浏览器/停止/持久读回不能由检查器单测替代。首轮失败须保留原因并重跑真实端到端，而不是删检查。
- Browser plugin not available，沿用既有 Playwright 静态层、预装 Chrome/CDP 真实层，无新浏览器依赖；CI-only `--no-sandbox` 继续明确记录，外层隔离不等于启用 Chrome sandbox。
- 原 `chengwang/Dockerfile`、offline 镜像和 M2b/探针镜像的浮动基础来源仍被原门阻断。本阶段是新增独立完整产品候选，不修改旧生产启动路径或给旧镜像放行。
- 只有实际通过后才能称 `PRODUCT_CANDIDATE_IMAGE=BUILT_AND_EXECUTED_ISOLATED`，始终 `authorization=BLOCKED`、`deviceActionsExecuted=false`。不解除九项恢复 blocker、M2b/M3/M4 或生产切换限制。

## 尚不承诺的事项

镜像远端发布/批准/签名、Registry 远端读回、独立 builder/source 证明、SBOM/漏洞治理、多架构、企业 IdP/审批、生产证书生命周期、完整企业 UI/多内核/DNS/订阅/节点业务能力、长时间 soak、分布式 HA、备份恢复演练和生产灰度读回仍需逐项完成。不得用本轮候选镜像测试给出全项目完成率、可用率、免维护或无 bug 承诺。

本阶段不访问或修改任何生产主机、爱快、DNS、OpenClash、Kuma、ERP 或生产 Docker；不合并 main。任何后续生产变更仍须明确授权、先备份、验证恢复并分阶段验收。

机制参考（不替代本项目执行证据）：[Docker 空基础镜像](https://docs.docker.com/build/building/base-images/)、[多阶段构建](https://docs.docker.com/get-started/docker-concepts/building-images/multi-stage-builds/)、[none 网络](https://docs.docker.com/engine/network/drivers/none/)、[构建证明的存储边界](https://docs.docker.com/build/metadata/attestations/)。
