# D12 真实产品异常来源与顺序追代：第一批协议

状态：实施中、未运行验收。既有来源 fixture 前置门通过，不代表本门或完整来源矩阵通过。生产环境禁止变更；只在隔离 CI 中运行实际候选镜像，根代理负责集成、提交与证据复核。

## 本批范围

每种签名格式（message-signature、dsse）各运行三个独立格，共六格。每格单独的信任库、证据库、身份、产品容器和来源进程，使用正常 TLS，来源计划通过私有文件原子替换，无 HTTP 控制接口。产品使用默认非测试入口、实际同一镜像，不直接组合后端、不手工调用确认刷新、不发送 catalogue PUT、不调用 SDK 验证接口。

| 流程 | 必须实际观察的行为 | 最终持久状态（预期，待实际验收） |
| --- | --- | --- |
| http-recovery | 403 不写库且未确认；G1 同代确认；再次 403 后自然陈旧；重新提供原 G1 恢复 | G1、sequence 1、journal 0、audit 0、ledger 0 |
| bad-signature | G1 确认；形状合法但签名损坏的 G2 完整拒绝；至少三次实际坏目录请求；同 base/raw 重复不追加拒绝审计、不续保鲜；自然陈旧；有效 G2 自动恢复 | G2、sequence 9、journal 2、audit 4、ledger 0 |
| prefix-recovery | G1 确认；latest 指向 G3，G2 有效、G3 坏签；G2 实际提交、G3 完整拒绝，整批不确认；随后有效 G3 自动恢复 | G3、sequence 13、journal 3、audit 6、ledger 0 |

首次 Apply 拒绝可以正常记录 journal/audit，不与 Fetch 失败的零持久写混淆。合法前缀可以提交，不能宣称整个下载批次原子应用。Fresh 必须比较实际观察时间与原 Until；不改系统时间、不以睡眠结束直接认定陈旧。来源响应只证明本端发送，不等于产品应用或确认。来源请求完成、后继请求和实际 API/持久 ACK 共同形成动作完成证据；不能把计划刚切换时仍在途的旧响应误判为续保鲜缺陷。

403 负例须由原计划、真实请求事件与完整已写响应头绑定；客户端不必读取完整错误正文，不能据此误判异常。200 候选仍要求原目录 bytes 对应的完整 wire 发送，并由产品实际代次、ACK 与 Fresh 独立证明接受。若错误正文未完整写出，须单独计数，不能冒充完整响应或成功下载。

本批不包含 SDK/Registry 读取业务，每个运行窗口应为零 Registry 请求。准备阶段仍须通过真实 Registry 上传及正常 TLS 字节读回证明配置、manifest、层和实际候选镜像一致。每格正常 SIGTERM、exit 0、离线重开并验证真实 journal/audit 绑定；所有拥有的容器、来源与私有树精确回收，保留外层镜像和原归档。

## 实施边界与独立证据

- A：新增带 productregistry/productlifecycle/productsource 标签的 Go driver；只准备测试材料、调用真实 API、发布有界来源计划、读取及重开实际持久状态。支持带 sequence 栅栏的 History 分页，不依赖单页完整性。
- B：新增独立 checker 和具名反例测试；直接绑定公开临时 anchor、原始目录 envelope/payload、原计划、来源事件、API 投影、实际离线 journal/audit 和 graph。独立验证 Ed25519 签名，按 operation ID/trace/hash 关联审计，不以“已验证”布尔值代替原证据。
- C：新增隔离运行器；真实产品默认 PID1、最小权限、只读配置与仅两处持久可写挂载；来源依靠原子 ready 加实际进程 profile 就绪，不以主动 TLS 探测污染产品来源请求。工件闭集、安全投影、逐格流量预算、实际退出和清理都要校验。
- 根代理：严格 product-source profile opt-in、合成 profile 测试、编译/CI 接线、交叉审查、真实 CI 及独立工件复算、失败与结果归档。旧来源 fixture、普通/race 728、父项目 2320 及所有原镜像门不得删减。

固定产品私有路径为 `/tmp/chengwang-product-lifecycle-<32hex>/refresh/<flow>/<kind>`，来源路径为同根下 `source-<flow>/<kind>/feed`。flow 仅上表三个闭集名称；现有旧 profile 和默认检查器 CLI 不获得新路径权限。无新的产品故障注入开关、私有协议或生产访问。

## 未完成范围必须保留

后续仍包括 TLS CA/SAN/SPKI 单因拒绝与同进程恢复、完整 HTTP/帧/超时/hint/gap/fork/两类 64 上限及字节预算、重启冷确认、实际 RESERVED 期间撤销的内核 blob 屏障及坏签对照、最终消费后的独立屏障、长期 soak 与正式发布/authority/生产灰度。第一批通过也不能替代这些内容，不能换算为完整系统完成率或互联网可用率。
