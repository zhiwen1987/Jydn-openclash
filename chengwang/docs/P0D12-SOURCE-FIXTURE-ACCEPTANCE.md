# D12 异常HTTPS来源fixture前置验收（2026-10-23）

结论：本前置门 `implemented+tested isolated-only`。它补齐可观察的异常HTTPS测试源和独立检查器，不是产品完整来源拒绝/追代/在途撤销矩阵已通过，也不是上线。root及两名独立子代理分别下载原工件、核源码并重放一致。产品运行逻辑未改；无SSH、生产配置、main合并或正式发行。

## 1. 接受代码及原始证据

接受代码 `57fd54c56a256da04ceb3f28e5450e56dab062a8`，attempt1。后续文档归档提交不是另一个已验运行镜像。

- [绑定运行39871985050 / job120148358838](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39871985050/job/120148358838)：completed/success，全部步骤success。
- [父运行39871985012 / job120148358676](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39871985012/job/120148358676)：completed/success，同一完整head。
- 工件12467008999，`image-binding-39871985050-1`，1280个原文件；ZIP5,919,982B，SHA256 `e99098659c589b611ae42519e213ca3a6a922f39d6d9476337f62951cff7cff9`。多份独立下载与API digest一致，root解包前检查全部entry为安全唯一平面名称。CI保留14天，不是长期备份或WORM。
- 绑定job原API日志2,015,496B，SHA256 `9b0c71641345b71dfa2af86737b3743984fb16d8c2f520d21cf6b2dfe45ceced`；父job原API日志5,447,093B，SHA256 `a8b742e90c6e3668c1b20401385d31fc033b5cb8e3d7c6bb0b1e5b06640abc2b`。没有用`gh run view`包装输出代替原日志。
- 新preflight原报告SHA256 `e35af9c3a8e3a0a9387fc70b84e7941198ecb73b39f1a880892c77fa89284bf1`，三份独立CLI重放canonical与其逐值相同；四份输入摘要与八份原Git源摘要均复核。

| 本轮镜像身份（只用于原门回归） | 实际值 |
| --- | --- |
| 产品静态二进制SHA256 | `1c0f2bab5fd7d6a34c13b3b70e7ae1b0fe95b870280467cfbedca4241faf14d2` |
| Docker imageID / config digest | `sha256:ffc8039df5ca18c1799c1be7aa9240aeee401107a896e3aacf76a7db5a3d1975` |
| 私有隔离Registry manifest | `sha256:bf054cccee45112ad2ae0241c8ef7fa3b4dc1cf0b58c255af895a13643f10e88` |
| 发布边界 | `EPHEMERAL_TEST_ONLY / authorization=BLOCKED / production=false` |

root副本：`C:/Users/Administrator/AppData/Local/Temp/chengwang-source-57fd54c-root-9d408f23c06541d692816a2f5870b8aa/artifact`；原ZIP/API日志和独立replay/root-audit-summary在artifact目录外，不混入1280计数。Temp不保证永久保存。

## 2. 实际新增能力与安全边界

按[固定协议](P0D12-SOURCE-FIXTURE-PROTOCOL.md)新增fixture_source、真实测试、独立checker/反例和独立CI runner，旧fixture_feed及其测试保持不变。源码对比证实本阶段没有改动product/truststate/refresh/命令产品运行逻辑。

- 测试源只监听隔离loopback；无默认路由、无HTTP控制接口/自选URL/header/延迟/命令。helper实测UID/GID10001、无补充组、cap0/NNP，源码只读；root只作测试编排，不把它当产品权限模型，也不声称host Unix sockets已隐藏。
- 私有目录0700/文件0600、无链接/特殊文件/未授权替换，实际打开FD核非plan inode；只有plan可原子替换。计划精确schema、单调epoch/同epoch原bytes防分叉、body原SHA绑定；ready原子、已有输出不覆盖。
- 19个闭集wire mode：正常JSON、403/503/302、缺失/重复/错误Content-Type、Content-Encoding、Trailer、chunked、缺失/零/超限/短Content-Length、截断body、超限header、固定stall及headers前关闭。每种由真实TLS客户端读取原wire并与独立公式核对，不由HTTP库规范化后反推原wire。
- 每连接connect/tls/http/close固定19字段，实际本端send返回量、计划/representation/wire SHA分别绑定；不输出请求正文、认证值、任意URL/query/异常文本或私钥。发送完整只代表本端API收下字节，不代表客户端业务接受。
- 固定2s socket timeout、8worker、512connection及4096event上限；TERM/INT/deadline取消并join。容量实测仅9连接/8worker，不称512耗尽实测。新子mount namespace精确私有/tmp清理完成，hostTmpTouched=false、parentMountNamespaceChanged=false、testExitCode=0。

## 3. 本轮实际测试与观测

fixture套件24项＝8格式测试＋16真实Linux用例，在CI全部具名通过、0skip；独立checker32项合成正反例也全部具名通过、0skip。合成checker测试不证明产品业务。固定具名集合SHA：fixture `0cd062d4a12483c0dfc94c3140ab2b3dc3c2beb7ab76fe26c8d3d8e45e7aaf59`，checker `c9fbaabbe28e93a8d5ad7dab8c67dcd8aca804fc09a8bda03b657a0b56ce2dd1`。

原observations SHA256 `b4408db26125bddf55cd7a8ebd6e5f6e966e621724de9c62729973101e4d1f6c`。闭集34个已启动测试源观测分段，共54个连接、201个事件、40个HTTP阶段事件、40次服务端TLS成功、2次failed与11次stopping结果，另1个容量拒绝无TLS；不是34次总进程启动或40个成功HTTP响应。40个HTTP事件包含headers前关闭的status0，以及2个未完整wire（stall-body完整header之后、body之前停机，stop-int零write）。

- 正常latest与2.json路径、CA/SAN负因客户端、19wire实际原bytes、epoch1→2→同epoch尾空格分叉→回退1→恢复3、敏感请求脱敏、body不匹配/丢失/非plan原子换inode、原输入不修复均具名验收。
- 第9个连接在TERM前已connect→close/closed；其close ordinal10之前，前8连接只有connect，实际/proc/task至少9。checker独立核原序列，不能以停机后的无TLS关闭伪装容量拒绝。
- stall-body由客户端收到完整固定响应头形成进入点，再TERM，核实际writtenBytes恰为header长度且wireComplete=false。stall-headers没有进入屏障，不用睡眠猜测补造在途证明，仅验完整wire及可取消实现。

## 4. 失败不抹除与加载修复

[原失败记录](P0D12-SOURCE-FIXTURE-FAILURES.md)保留3573被格式修正替代、5d真实启动失败及7e安全诊断失败。7e实际确认`BOOTSTRAP_MODULE_NOT_FOUND_SOURCE`，没有据此臆称具体目录EACCES。

修复仅移除低UID从checkout路径import的新增前提：可信root从只读Git绑定文件读取两个原模块bytes，经有界stdlib无损封装传入`-I -B -c`；子进程核原长/SHA、解压上限和结束状态，注册固定module/sys.modules后执行，最后仅显式main。无可写helper源码副本、PYTHONPATH、目录权限或身份限制放宽。Windows真实加载smoke只作辅助；本轮最终依据仍是上节实际Linux24项及原始观测。

## 5. 原全部回归与来源复核

普通/race各728个实际具名Test* run/pass、0Test skip/fail，保留原700＋既有28；完整名单摘要仍 `6557b5f9621b6d691133c2242ab1c35308dfcd376424b43c6a9c2644830d0811`。Registry普通/race各3，父普通/race各2320，父名单摘要 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8` 不变。

| 原门独立canonical重放 | 本轮关联数 | 本轮原outcome SHA256 |
| --- | --- | --- |
| D11 Registry/签名/批准/撤销/重放 | 49 | `da0a193d6a6dc277b94be32bd59ded4583320947753020e312d20de6f51a2727` |
| D12正常自动刷新/陈旧/恢复/重启 | 65 | `be15ee6b9465ad75ced83dc794189b1e15147579bc1042e6ef26abaac744cae9` |
| D12实际三阶段中断 | 151 | `06bef50a5e4adbdde6e0a4010d24e8b8968581de9094e402b11d9ff26bb189a3` |
| D12预置状态启动矩阵 | 909 | `657c80c420e1e94e366dcd95b35450b02f9360b45ff682f57bcb2eaa3e546303` |

原浏览器40/45/45、lease20/feed34/checker13、native14、crash profile6/verifier27、state profile8/verifier32及精确清理保持。旧crash仍6次137/12次正常0，预置门仍36健康/48拒绝、672快照/168启动零请求窗口、72正常0/96自然拒绝1、85所属容器清理，不能把预置态改称真实crash。

checkout605条＋子模块source90条＝695条/605唯一文件；两组before-after原bytes均一致，全部声明摘要逐Git原blob复核，无CRLF归一化，不沿用此前686/597等旧计数。

## 6. 未完成及下一步

明确`fixturePrerequisitesOnly=true`、`actualProductSourceMatrixProven=false`、`productTLSRefusalProven=false`、`productAutomaticRefreshProven=false`（均指本新门）。原门已有的正常产品刷新证明不被否认，也不能拿来补本新门缺项。

下一门仍须接入真实镜像来源拒绝/顺序追代/合法前缀后拒绝/在途撤销，绑定实际产品状态、原签名候选、审计与Registry预算。特别是：

- 当前stall仅0.75s，小于产品refreshTimeoutSeconds的整数秒下限1s，不能证明真实产品超时；stall-headers自身503也不能冒充timeout。需另补明确跨越产品正常timeout的闭集hold/独立屏障，不降低产品限制或修改时钟。
- 真实坏CA/SAN/SPKI必须单一负因且产品保持正常API就绪，不用startup exit1代替。runner自身readiness TLS probe必须排除在产品尝试证据窗口外；不能凭空HTTP日志或服务端异常文本断言客户端拒绝原因。
- Fetch失败无部分batch；Apply逐代允许合法前缀提交；失败不Confirm，原Fresh须自然过期而非伪称即时false。Fetch64代预算与Store总history64上限、下载4MiB与历史4MiB也需分别验证。
- 其他真实故障边界、持久去重/完整DoS防护、坏盘/断电/整盘回滚、长期soak、正式authority/IdP/Registry发行、企业功能及生产灰度仍未完成。九项恢复blocker不解除，不承诺可用率或零bug。
