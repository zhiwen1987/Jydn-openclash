# D12 异常来源独立fixture协议（实施中，未验收）

本门是完整镜像来源拒绝/追代/在途撤销矩阵的必要前置，不替代后续实际产品镜像门，也不缩小企业系统目标。生产禁动，root唯一集成/提交/推送；旧fixture_feed及34测试、所有原700+28普通/race、父2320、全部镜像门保留。上一拒绝保护接受代码ed756d7及归档83d1dea不改写。

## 职责与文件

- A：新增`deploy/product-candidate/fixture_source.py`，独立闭集异常HTTPS源；可复用旧fixture_feed的严格路径/私有文件/请求解析实用类，不修改旧文件或猴补旧模块全局。
- C：新增`test_fixture_source.py`，闭集shape与真实Linux低权/TLS/退出测试；不继承旧TestCase导致重复旧测试。真实输出另写`product-source-fixture-observations.json`，不包含私钥/请求/header或任意错误文本。
- B：新增`check_source_preflight.py`和`test_check_source_preflight.py`，严格事件/完整具名测试/安全观测/来源原Git bytes检查，不只接受green marker。输入输出闭集，未知/漏项/skip/重复/伪造来源失败。
- root：协议、独立runner及CI接线、交叉审查、实际CI与独立下载重算、归档。当前阶段不修改产品逻辑或新增产品fault开关。

## fixture运行边界

保持现有Linux隔离loopback、无默认路由、源只读、独立mount namespace私有/tmp；helper必须UID/GID10001、无补充组、cap0/NNP，自检失败退出。沿旧`/tmp/chengwang-product-lifecycle-<32hex>/<case>/<kind>/feed`精确私有树；目录0700/文件0600，拒绝symlink/hardlink/替换inode。只绑定127.0.0.1，无HTTP控制接口、任意URL/任意header/任意延迟/命令或代理功能。固定socket timeout2s、8worker、512connection、4096event上限；TERM/INT/截止取消并join。上限耗尽失败关闭，不静默丢弃日志。ready原子且不可覆盖。

可复用旧PrivateFiles，但新子类必须独立audit_entries（新body上限262145B、至多128个）及新plan解析，不放宽旧fixture256KiB限制。计划仅私有原子文件，schema`chengwang.product-source-plan/v1`，精确字段schema/epoch/responses；epoch正uint64、同epoch原bytes变化或回退拒绝；responses至多65项，key仅latest.json/正canonical generation.json。每项精确mode/bodySHA256；mode为下节闭集，bodySHA256为64lowerhex或约定空字符串，不接受自定义header/目标地址/延迟。body文件以实际SHA绑定，输出不回显body。

## wire闭集与日志语义

mode固定为：json、forbidden、unavailable、redirect、content-type-missing、content-type-duplicate、content-type-wrong、content-encoding、trailer、chunked、length-missing、length-zero、length-oversize、length-short、body-truncated、header-oversize、stall-headers、stall-body、close-before-headers。

无输入body的mode：forbidden/unavailable/redirect/stall-headers/close-before-headers，digest必须空；其余必须实际有界body。403/503/302及redirect的Location为编译期固定值/路径，不从输入反射。header-oversize固定17KiB padding；length-oversize声明262145；stall固定0.75s且可被stop立即取消。malformed wire是fixture能力，不先验宣称产品必拒绝全部mode，尤其length-short不能凭尾部额外bytes推断产品一定失败。

采用每条相同精确字段：schema/ordinal/connection/event/reason/epoch/planSHA256/pathClass/generation/mode/status/representationSHA256/representationBytes/wireSHA256/wireBytes/writtenBytes/wireComplete/authPresent/tls。

- schema=`chengwang.product-source-event/v1`；ordinal从1连续，connection从1分配，event闭集connect/tls/http/close。每个connection恰一connect、零或一tls、零或一http、恰一close；允许并发事件交错，但连接内顺序固定，不假设epoch全局日志顺序单调。
- connect/close和无HTTP的tls事件不伪造plan/路径/状态/bytes，非相关字段为0/空/false；tls字段仅反映本连接是否服务端握手成功。connect reason=accepted，tls reason=ok/failed/timeout/stopping，close reason=closed/stopping；HTTP reason=planned或固定拒绝码，禁止任意异常文本。若worker容量已满也须记录connect→close，不能默默消失；容量拒绝不伪造TLS。
- http绑定实际选中的epoch+原planSHA；固定pathClass=latest/generation/invalid、实际generation、mode/status和完整拟发送representation/wire摘要；writtenBytes只计socket.send成功返回的bytes，wireComplete表示所有计划wire已交给本端TLS/socket API，不表示对端已读取/接受。
- TLS失败仅固定enum，不根据server ssl异常文本猜测CA/SAN/SPKI原因；SPKI拒绝可能服务端握手成功但无HTTP。后续真实产品矩阵必须绑定单一负因配置、实际连接观测和产品拒绝/状态，不能凭零HTTP日志宣称TLS尝试。
- 所有日志最大4096条、每行固定字段，绝不保存raw请求、Authorization值、URL/query、证书私钥、任意异常。敏感请求最多authPresent布尔；响应固定错误表示不反射请求。

## 测试与机器验收

helper和test接口由A/C据此对齐，冻结后root接线。真实Linux测试使用独立openssl测试CA/leaf，正常验证，不用CERT_NONE；负CA/SAN用单因测试客户端证明fixture可记录连接/握手，**不是产品拒绝证明**。shape-only在Windows可运行但不能生成Linux PASS。真实失败不skip；缺工具/权限失败。

测试导出观测schema=`chengwang.product-source-observations/v1`，精确schema/cases；cases为每个真实测试实际启动的fixture分段，精确testName/label/events。testName为直接LinuxTests中具名test方法，label为闭集安全case token，events为原JSONL解析数组。真实成功启动必须非空完整日志，启动拒绝case可以没有分段但必须在测试断言退出与原bytes保留。所有段必须通过独立checker连接状态机；checker验证固定必须出现的正常200、真实403/302、固定wire模式、TLS失败、错误请求/无敏感值、plan回退/分叉及取消/stop记录，不仅数测试。观测只证明fixture，不发布候选目录/批准能力。

实施冻结的具名套件为24项（ShapeTests8+LinuxTests16），Linux不允许skip；另32项独立checker合成测试（含正例和反例）。真实观测闭集34个label分段，不等于全部启动进程数（启动拒绝子用例不伪造成功段）。19个wire mode逐一实读原bytes；仅stall-body通过客户端收到完整响应头形成确定进入点，再TERM观察不完整write；stall-headers没有“进入stall”观测屏障，只验完整wire及静态可取消逻辑，不用睡眠猜测补造在途证明。容量实测9个连接/8worker，不冒充512连接预算耗尽实测。

checker从准确head Git原bytes提取测试名和source SHA，核全部ok/唯一summary/marker/0skip，拒绝未知输出；验证新runner实际清理成功，并绑定所有fixture/checker/test/runner接线原blob。报告显式fixturePrerequisitesOnly=true、actualProductSourceMatrixProven=false、production=false、authorization=BLOCKED。单元checker反例使用synthetic数据，必须标注，不能当真实Linux证据。

CI另起`run-source-fixture-preflight.sh`子mount namespace，旧前置门不改。四个原输入为product-source-fixture-tests.log、checker-tests.log、observations.json、cleanup.json（均带同一product-source-fixture前缀），输出product-source-fixture-preflight.json；原Git来源8份：旧fixture_feed.py/check_lifecycle_preflight.py，新fixture_source.py/test_fixture_source.py/check_source_preflight.py/test_check_source_preflight.py，新runner及run-linux-ci.sh。Windows辅助目前Shape8通过/Linux16明确跳过、checker32合成通过；这不是Linux验收，仍待实际CI及独立工件重算。

## 后续不可丢弃

fixture门通过后再接真实镜像来源负矩阵：CA/SAN/SPKI单因、HTTP/帧/timeout/hint/gap/fork/预算/取消、Apply重复拒绝、真实顺序追代与合法前缀后拒绝、no-op/自然陈旧/恢复/重启冷确认、在途撤销内核屏障及精确清理。完整签名/原bytes、产品状态、审计和Registry预算分别绑定，不把Fetch无写与Apply合法拒绝审计混为一谈。长期soak、全部故障边界、正式authority/发行、企业功能和生产灰度仍在全目标中。
