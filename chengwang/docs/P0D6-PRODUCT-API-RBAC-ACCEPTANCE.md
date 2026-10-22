# P0-d6 产品 API、RBAC 与受管信任验收

日期：2026-10-22（Asia/Shanghai）。结论：本阶段已实现并通过隔离验收（implemented+tested isolated-only），不是生产上线或部署批准。仅开发分支与隔离 CI，本轮不访问或修改生产。

## 实际实现

- 主项目保留 Go 1.23。新增 `internal/imagetrust` 纯接口/DTO，产品 `api.New` 注册受保护接口；独立 Go 1.25.8 `product.Service` 接入真实 Store、ManagedBind 和 evidence。没有用主模块直接依赖新版 SDK 或升级整仓 Go。
- API 与后端双重 RBAC。信任对象的 tenant/site/object/environment 由服务器固定；HTTP 身份来自真实 authn，body 不能注入 principal、scope、Anchor、CA、Registry token、URL、时间或授权 nonce。三个动作不允许 break-glass，也不降级使用旧 AdminToken/cookie/转发头。
- GET `/api/v1/image-trust` 返回当前 catalog、撤销计数和 grant 消费安全摘要；PUT `/api/v1/image-trust/catalogue` 只允许 admin 安装下一代有效签名 catalog；POST `/api/v1/image-trust/verifications` 只允许 operator/admin，消费 grant，因此同样受独立写门保护。
- 认证、TLS/直连回环、RBAC、写门与 body 预算先于后端；后端直接调用也重新授权。规范字段/base64、重复/别名/未知字段、query、Content-Encoding、Content-Type、decoded/总字节预算均有拒绝测试。
- 实际预审计与结果审计不保存凭据或原始 bundle。两库非原子，提交/结果审计不确定时返回 `stateMayHaveChanged=true`，不返回成功、不自动重试、不回收 grant；当前 Service 实例永久失败关闭。
- `verification_consumed` 只表示真实验证与持久消费完成，不表示 HTTP 成功或客户端收到响应。结果审计后再次检查当前 catalog 代际/撤销/active grant/CONSUMED 摘要和较早到期时间；公开 Receipt 只是 advisory DTO，不是部署权限或可重新导入的 ManagedResult。
- 增加只读 `Summary/Inspect`，不前进账本 sequence 或时钟高水位；过期可报告但不能继续用于信任消费。

## 原入口与候选入口的区别

`cmd/server` 源码没有注入这个可选后端，新接口默认未配置、写门默认关闭。没有重建、安装或更新生产原入口，不能把注册接口说成线上服务已提供。

独立候选 `tools/image-binding/cmd/image-trust-api` 实际调用同一个产品 `api.New` 并注入真实后端；仅开放 health 和三个 image-trust 路径，其余版本/发布/操作/设备端点不开放。它不是新建一套 mock HTTP API。

候选读取独立私有配置、Anchor、公钥 CA 与真实身份文件；literal UTF-8/exact JSON 拒绝重复、大小写与转义别名。只打开已存在的 Store 与审计 log/checkpoint，缺失拒绝而不初始化。`writesEnabled` 缺省 false，非回环必须 TLS，配置文件 0600、目录 0700、no-follow/单链接/所有权检查，配置路径绝对规范。操作说明和构建命令见 [模块说明](../tools/image-binding/README.md)。这些是候选约束，不是可信引导工具或生产密钥分发。

## 最终隔离验收

最终代码与场景门提交：`5107ebd5b51f42d9b70cddf3027b4626ade99942`。以下来自已完成的任务及下载后的原始附件，不以 workflow 定义或旧提交结果代替实际执行。

| 项目 | 实际证据与结论 |
| --- | --- |
| 绑定模块任务 | [run 39763836641 / job 119774275129](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39763836641/job/119774275129)，success |
| 主项目任务 | [run 39763836481 / job 119774274234](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39763836481/job/119774274234)，success |
| 子模块普通/race | 各 490 个精确 Test 场景、7 包、0 fail/skip；两份集合一致，保留原 234 与 379 场景指纹；product 47、候选 cmd 完整 46 场景均锁定 |
| 主项目普通/race | 各 2252 个 Test 场景、37 包，合计 4504 个语义运行事件，0 fail/skip；原 2067 场景无缺失；新增 API/RBAC/DTO 场景受精确集合门约束。Fuzz 顶层及 seed 事件不混入 Test 计数 |
| 真实单链路 | 两类签名均经产品 HTTPS API、真实 authn/RBAC/audit/Store/Sigstore 访问无适配真实 Distribution 3.1.2；成功、持久 CONSUMED 与拒重放。普通/race 各 3 个测试事件，managed 与 product API 标记每类各恰好一次；144 次不可变 GET/HEAD 全部 200 |
| 故障与边界 | 真实 API 认证/范围/角色/写门拒绝不消费；网络中撤销与忙拒绝；消费后审计失效返回不确定失败、无成功 Receipt；候选 run() 实际 TLS 监听、错误 CA 拒绝、明文不可读取、默认锁定、缺 Store/审计拒绝、关闭与锁释放 |
| 源码/依赖 | 491 项跨模块源码与 49 项子模块源码前后相同；独立逐 Git 原始 blob 核对到最终提交。386 个远端模块版本及 go.sum 保持 P0-d5 集合；官方在线/离线模块校验通过 |
| 候选构建 | 实际 go build 与 --help；Go 1.25.8、trimpath、vcs.revision 绑定上述提交、vcs.modified=false。CI 报告 SHA-256：`acf9ec290f3007a96b6e05af3733ed7da4b21a5629aed9262c9bdbc6d2185119`。未上传二进制本体，不能把元数据核对说成下载重哈希或签名发布 |
| 隔离与清理 | 普通门仅回环、非 root、无 capabilities、NoNewPrivs、源码只读；真实 Registry 仅独立 internal 网络、TLS、无 host ports/持久 volumes。测试材料清理实际 PASS；34 份附件未见私钥文件或 PEM 私钥块 |
| 其他回归 | Go vet、158 个 Python 测试、13 个 shell 语法检查、11 份 schema 门通过；子模块 JSON 检查器 37 个负例通过。Actions 的旧 Node 运行时迁移提示仍存在，不宣称零警告 |

三个子智能体分别负责 API/RBAC、真实 Store/候选组合和 CI/独立证据复核；集成者再次执行精确 JSON 门并核对源码摘要。集成者证据目录为 `C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d6-ci-39763836641`，独立复核目录为同级 `chengwang-p0d6-review-39763836641`。本地 Go 缓存损坏未绕过校验，真正 Go 验收在隔离 Ubuntu CI 执行。

真实监听测试是在测试进程中调用候选 run()，构建产物只执行 --help；不是已安装 system service、完整发布进程的生产启动/SIGTERM 或正式镜像验收。此处“通过”仅指上述范围。

## 本阶段发现与处理

- 首轮 `59794e7` 主回归成功，但子模块因 Inspect 测试变量作用域错误及较早到期断言预期错误失败。失败不计通过；修复为局部声明、独立读取批准/catalog 并取较早到期，没有放宽产品检查。
- 提交后仍有结果审计 I/O：新增最终 post-audit 状态/到期检查，避免网络验证成功后策略已变却返回旧成功。审计标记区分验证消费与 HTTP 结果，不伪造跨库原子事务。
- 合法并发审计 append 可能穿插 Verify/Status 两次读取：采用不跨网络的短审计锁和有界重验，不因正常更新误判损坏，也不接受旧 cached head。
- 私有配置/身份文件原 JSON typed decoder 接受大小写别名：增加精确字段形状检查，同时保留合法显式 false/omitempty 与类型化时间标量；不靠拒绝所有可选值蒙混通过。
- 候选曾暴露未配置 Versions 的原产品路由：改成固定 allowlist，不暗建无关版本库，也不把 panic/recover 视作正常失败关闭。
- 单元 HTTP→测试 Registry 与低层真实 Distribution 原是两条证据链：追加产品 HTTPS API→真实 authn/RBAC/audit/Store/Sigstore→无适配真实 Distribution 的独立 grant 验收，不能混称未测的完整链路。
- 通用 evidence.Open 可初始化空历史：候选入口额外要求已存在的安全 log/checkpoint，拒绝意外丢失后的静默重建；不改变其他产品用途的 evidence.Open 行为，不声称能检测恶意管理员整体重建历史。

## 未完成与剩余限制

- 没有部署到生产、合并 main、更新原发布镜像、安装服务、配置生产密钥或接入设备执行器；所有成功仍 `ADVISORY / authorization=BLOCKED`，九项恢复 blocker 保留。
- 没有管理 UI、企业 IdP/MFA/SSO、身份热更新、交互审批与离线根/HSM 流程。身份文件是静态快照，修改后需受控重开；API admin 不能代替 catalog 阈值签名。
- 单 Store 固定一个可信 scope，不是完整多租户 Store 路由、分布式租约/共识、跨站 HA 或大规模企业容量验收。
- 验证预算是进程内单并发、每分钟 4 次启动，不为任意请求建立无限 map；重启重置预算，但不重置 grant。它不是 SLA/企业吞吐承诺。目录更新没有独立的限频/配额服务；生产前仍需受控管理入口的全局连接、请求、审计磁盘配额与访问保护。
- 两库没有原子事务、持久 Service poison 或重启自动 reconcile；不确定结果需要按公共证据人工恢复，不可自动重发。审计不证明客户端收到响应；没有 WORM/独立副本、审计查询界面、长期归档、匿名拒绝路径的独立限额安全访问日志。
- 审计新鲜度是缓存且候选没有周期刷新任务；空闲超过 30 秒后 Status 可报告 Healthy=false，写操作会重新校验。不能把该状态误称完整自动健康维护或已经完成监控接入。
- 没有在线自动 catalog 刷新或即时离线撤销送达、外部单调见证、整盘/Anchor/审计历史一并回滚防护、运行镜像自动撤回或部署 exactly-once。
- 有效期、64 代历史、4096 消费账本等既有失败关闭预算不变；容量告警、自动归档/迁移与长期运维仍缺。
- HTTP 超时不等于中断 SDK 密码学 CPU；CI 进程限制不等于候选部署已有硬隔离，仍需正式工作进程/资源预算。未进行物理掉电、真实生产进程发布、长时间浸泡、完整企业安全审计或生产 SLA 验收。
- CI 附件保留 14 天，不是长期不可变审计库；候选二进制构建/帮助输出/摘要不是签名发布镜像、正式制品准入或生产启动证明。

没有因本阶段测试提升 M2b/M3/M4 或整体正式运营状态。不承诺绝对无 bug、100% 业务准确或 99.999999% 可用率。
