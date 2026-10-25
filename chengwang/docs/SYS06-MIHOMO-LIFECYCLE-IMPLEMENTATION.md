# SYS-06：Mihomo 发布闭环的实现进度

当前是独立开发分支：`9adbbe0` 的首次真实Completion四模式已限定隔离验收通过；9 ZIP／167成员、1381跟踪路径，四模式原checker main直接复演通过，root原始Go／命令／落盘计数独立复核，四组producer／fresh一致。新基础门ordinary 688／688通过、race仍累计180秒超时，不能把Completion成功当整个回归通过；诊断与旧S2仅本轮CI状态核实为success。先前c1f9与4bbbe限定接受保留为各自提交历史，不证明当前稳定余量。产品service换绑、新head后普通发布、产品恢复API、第二恢复及完整系统／生产仍未验收。所有历史失败保留，未部署到设备。完整目标仍是：完整工件 → 私有备份 → 范围批准 → 隔离灰度 → 实际重载 → 新鲜读回与数据面验证 → 失败回滚 → 重启恢复及审计。仅有PUT、204、配置生成或测试通过，都不能把SYS-06标为完成。

## 本次已有代码

本轮待Linux重验的保守性能修订仅把BEGIN／REVOKE的完整草稿构造闭合在各自私有入口，在原copyRecord已完成intact及JSON分离后，省去同栈重复的第二次intact。publisher整函数、trusted clone、prepare语义尾、磁盘verify/read/CAS/fsync/readback及Completion freshness保持原字节；generic／split入口仍保留原intact与marshal。真实256循环、2MiB、688必需名称与180秒均不变，尚未证明性能收益。先前v1的direct-proof跳marshal候选因typed/raw变异缺口被拒，v2新增MODEL又因两次随机fixture不能假设同raw而被拒；当前v3改为一次canonical raw分别克隆到两个独立MODEL disk/store，不修改rand.Reader。当前三个非test common-helper调用点经根静态核对；这是源码证据，不是运行验收。

### 恢复协调器、reconciliation 与产品 API 已合入，实际回归已进入，产品链尚待验收

`9adbbe0` 已取得新原件：首次Completion run40234883944的11任务成功，9 ZIP／167成员、1381路径、四mode原checker直接复演及root原始Go／命令／落盘计数复算一致；[接受记录](evidence/sys06-9adbbe0-first-completion-acceptance-20261026.json)只接受首次四模式，不证明service rebind、产品API、普通发布、第二恢复或生产。基础门run40234883862仍失败，其250290字节／13成员原件已核：ordinary 688／688必需、1990语义通过；race 584必需通过、零terminal失败、1运行时超时、103未起，包180.047秒。capacity为88.85秒；alarm时当前测试仅运行约0.497秒，不能据栈归因全部预算。47／25模型和空格式门通过，全部历史失败保留。180秒、256实际begin/revoke循环、2MiB与逐plan检查不放宽；性能候选须独审及同提交Linux实测，不能预称已有收益。新连续HTTPS候选仍是外部source，读取器复审发现序号偏移、合法zero-core及嵌套响应绑定缺口，正在新版本修订；31请求尚未实际执行。

完整私有WAL仍只有producer内复查与公开index/fsync旁证，不提升为独立全文证明。normal原件artifact12614223888 SHA256为`cc9ce1d8dbbd19ec78da718d161d828c394203349010b4fc5addc3d2176554bc`；[独立原件审计](evidence/sys06-9adbbe0-normal-contracts-original-audit-20261026.json)保留失败终态。下文6018及此前提交均为历史记录。

固定实际图后的 `6018ebbb23eb85ee87bb11557b959b461a8b42a2` 已通过 reflection 与旧 S2 CI 状态门，但新阶段仍未整体验收。ordinary 688必需中684 PASS／4 FAIL，无未起；race628 PASS／4 FAIL／1运行时超时／55未起，原文 `panic: test timed out after 3m0s`，180秒是包总预算，不能把当时运行的HistoryContext测试认定为唯一热点。原 normal ZIP267520字节 SHA `d5202b4031441563d47bc18544fcf29dfb2d70b2d86a7fa4f0f4da383892e439` 与 full ZIP541160字节 SHA `5a39da1fb4f5b05904ae590760d39134288babd04223e132f537e4bedbf6e130` 保留。

本轮仅修实际4个失败：authority的三处夹具及busy夹具改走现有armStart，补齐批准→StopIntent→quiescence→StartIntent后才记START_UNCERTAIN；record-context helper保留nil／budget／action拒绝，原样返回caller取消或超时，派生timeout／defer cancel／二次Err门不变；reserve MODEL把6个false→true在Recovery及其等值History尾两次编码的差异明确为12字节，不改production reserve／validator。688顶层名称、全部断言和180秒／256历史／2MiB门保持，race性能仍需独立关闭。

同提交首次Completion四mode均在Go前被worker仍写83／84／661的合同拒绝；JSON／reader已为84／88／688，属于执行器同步遗漏，不能称Completion真实运行失败。现只同步这3计数，旧capture／pidfd／预算字节不改；在既有11个CPU顶层内新增直接执行真实producer.contract与actual sibling JSON／实际compat.decode的回归子例，只模型化受限文件读取，旧counts／float／bool必须拒绝。初次辅助回放误用严格compact报告decoder读取pretty合同而拒绝，已改用真实compat decoder，原失败保留，修正单顶层CPU通过；此CPU结果不代替下一Linux四mode。

修正提交 `69c2fc29e63e6f3c8c0cd993757a225a74d58782` 已在真实 Linux 编译并进入 mihomodeploy 测试。full diagnostic `40231324060` 的 artifact12613366005为470958字节／21成员，SHA256 `484b95eea7b5d0b02cefb0092aaff83f287e98684565f0854310b53a4dcc4edf`；1379路径来源前后相同，root逐Git blob／SHA再核。唯一诊断 top 的实际 output／pass给出 digest `ee925968d830156c5a5c0c366e28722e278b1d54284712ebc28b47a8ed7e4d61`、63结构、457字段、86可变槽（67指针／19切片），另一个digest MODEL同值PASS。root原件审计收据 SHA256 `bb7d009d2d84217bf91ed75cfe6d1049789018e1237d61f46f2675d4640b7ba0`。

据此只固定该实际图pin，并把现有属性覆盖门59→63、82→86及对应诊断文案同步；不删除任何复制／逐槽／canonical／来源校验，也不改变克隆算法、记录格式或权限。full仍为Go exit1、116顶层失败，此前空pin是已知阻断，不能推断全部失败均无第二原因；下一同提交实际回归才决定是否通过。该反射元数据不是产品API、真实恢复成功、完整私有WAL或生产证据。

后续修正提交 `a433cc9750a0d22b401202cfc4ddddc7053c4294` 的真实首轮仍失败，但前两项阻断已排除。foundation `40230016584` 的 47／25 名称模型门通过；ordinary／race 每套其他五包各746个 test run／pass，mihomodeploy 在 MODEL 测试编译阶段报 `binding.TargetArtifact` 不存在。helper 第四返回本来是 `labRecoveryPlan`，第五才是仅含旧身份的 `labQuiescenceBinding`；当前仅保留第四返回并从 `plan.descriptor().TargetArtifact` 取该夹具目标，30处引用更正，旧身份、58断言、7顶层保持，没有向生产绑定结构加字段。独立预测与root实际组合 SHA256 均为 `b6c1638cacda580faf0ea42ef1837e92600b95331c6edf2e21f31f3eebf3321c`。

本次完整144个Go格式目标实际产生78781字节补丁，SHA256 `bd6830e43564e289a22cef20f30bcde35cf208fc9a533ff8afcc06a9d80765a7`，10文件／54hunk。root逐Git前像严格重构后与独立formatter后像逐字节相同，再对唯一交叠MODEL文件叠加上述语义映射；其余9文件完全等于官方后像。未运行本机Go／gofmt；原编译失败与非空格式门不改判。独立 full diagnostic `40230016615` 同样没有结构诊断 run／output／pass，所以本轮仍无pin或结构计数，下一真实Linux结果必须重新取证。

首轮源码提交 `a9774e526735086a683b57f615b639791b9498e0` 已取得实际失败，不是待运行。foundation `40228540529` 的 47／25 CPU 模型通过后，在 Go 前的名称摘要门失败：25 名称应为 `e8c92e60d45a0922815116ab808d1d45ad840a0fa433a942af98fdd37a59f799`，工作流误用了模型文件摘要 `d9d70...`。独立 full diagnostic `40228540473` 真正启动 Go1.23.12 后编译失败，coordinator 的 643／884 行引用缺失的 `newLabRecoveryCollectorAt`。原 artifact 12612022850 为 240931 字节，SHA256 `88c69db620c06b7f6e61f26ce25f23e61bf34fff523cc35208833b058de6aab9`；18 成员与完整 1377 路径来源已由 root 独立复核。没有 diagnostic top 的 output／pass，故没有新图摘要或计数。root 有限失败收据 SHA256 `17b0c6751da91d252d0e18779a81319f7e52a8170b1866c4a0594299fb866e8e`。

当前最小修订仅恢复该名称摘要并补 collector 的派生目录接缝：At 构造与 collect 写入前均从 exact registered session／authority／RecoveryID 重算 stage，同一个局部 stage 用于 transcript、8 bodies、local marker、verification；旧 constructor 和 marker wrapper 仍固定 `recovery-s2`。no-replace、容量、授权、current kernel 与取消门保留；回归只扩展原顶层的子例，688 名称不变。独立有限审查允许进入新 Linux diagnostic，不能据此宣布已编译或 API 通过。旧 full artifact 格式差异虽为0，但它只格式检查10文件，不覆盖完整144文件或本次新改3源。

在已接受 `4bbbe70` 的隔离开发工作区，主集成者按冻结清单逐文件合入 37 路径，并保留此前四份任务文档及首次 Completion 接受记录。来源补丁 SHA256 `529e80f52fbc7dec6867bbbe9466c4d1fa39e95bfd30db41148e0bee04cd43f7`；重基独审收据 SHA256 `d0cd138ee1bf3a7404c7a7691284210b803ebee86f4f59aeb5fce0227ef1fbb5`。36 后像保持前一 v4 候选，唯一 checker 重叠只更新来源闭集及旧 native-v5 摘要，保留正式 alias、11 模型与 Go 格式后像。这里的合入不代表 Go 编译、运行通过或上线。

源码新增真实 recovery backend／Linux coordinator 和 API 接线、暖进程失败后的有界 reconciliation、明确未启动 owned wrapper 清理、source-owned current epoch 接续。fresh 授权先于状态响应与重试预算，重锁后复核 exact operation／custody／WAL；完成提交继续使用独占 Completion publication 和 opaque handoff。CI 声明闭集变为 150 源／58 必需测试源／688 顶层／88 六包测试源／144 格式 Go 文件／188 native 来源；新 27 个顶层只是声明，尚未实际运行。

新增结构的 `lifecycleCloneSchemaSHA256` 暂为空且 fail closed，不用旧 `6b46` 摘要或推算结构数。现有 `TestLifecycleRecoveryCompletionActualCloneShapeDiagnostic` 会直接输出实际 Go reflection digest、structs、fields、mutableSlots、pointers、slices；下一 Linux CI 必须从同提交原始 JSONL 的唯一 output 及实际 pass 取得，再单独冻结 pin 和属性门。若编译失败则没有这条实际证据，须先修编译。首轮诊断或其他测试因空 pin 失败不能记作验收通过。

真实连续 API 验收仍缺。旧 fault-tag 胶囊消费一次后拒绝后续匹配 PUT，即使下一 ordinary Execute 新建 WriteClient 也仍绑定同一进程 issuer；因此连续实验连第一次恢复后的普通 ACK 都不能用旧胶囊代证。默认无 fault-tag transport 不受此实验限制。新连续实验必须另设 operation／epoch 绑定、总两次注入且普通 ACK 放行的独立测试合同，不能 reset 旧 issuer、更不能改旧 native 合同来伪造连续性。完整 API／普通发布／第二恢复、UI、冷重启与生产仍未验收。

### 4bbbe70：首次真实 Completion 四模式限定隔离验收通过

精确源码 `4bbbe70b1f13e53fa07201e32129366cf254ccee` 的新运行 `40226840814` 共 11 任务全部 success。固定 9 原件 ZIP／167 成员按认证 API 摘要、CRC、安全路径与原字节独立核对；四种模式均直接复演原检查器 main，无平台适配或诊断副本。root 另行独立重数真实 Go、四类命令、模式计数／revision／adopt／poison、格式和输出一致性；[聚合收据](evidence/sys06-4bbbe70-first-completion-acceptance-20261026.json) SHA256 `ea936d1bfd27c36f725afae251d81dca23a2ed8a58ce6268c32f0012eaebe8b5`，详见[完整独立审计](evidence/sys06-4bbbe70-first-completion-independent-audit-20261026.json)。

positive 在 Completion 点实际 replace／forward／read／injected 为 1／1／1／0，内存与磁盘 revision19，opaque runtime 首次 adopt；NotCommitted 为 1／0／0／0，内存与盘 revision18，冷开按正式 opener 转 UNKNOWN；Unknown 为 1／1／0／0、坏读回为 1／1／1／1，内存18／盘19，二者均 poison 且不 adopt。实际 cap 一次消耗／重放拒绝、19 native 事件（Completion 前缀14）、4 WAL 索引／10 fsync 回执、五端口拒绝和 fixture／runtime／disk 关闭均核。四种格式差异均为0。

此结论只覆盖固定隔离内核的首次 Completion 与 positive 首次 opaque runtime adopt。完整私有 WAL 未供独立读取，仅 producer 重验及公开索引／fsync 绑定；serviceRebindProven、apiRouteProven、ordinaryPublishProven、secondRecoveryProven、production 全为 false。其他三条同提交 CI 终态成功只作状态观察，本轮不再用未变旧门的重复下载扩大新结论。`fdc2587` 与 `a9882e4` 失败均保留。下一外部 v4 协调器／API 候选已完成授权顺序修订、独立源码审查与重基，仍须真实 Linux 编译、图 pin、格式及端到端验收。

### 历史：a988真实Completion Go已进入，独立门仍失败

当前工作区已接入独立的首次真实Completion隔离CI源码入口。`a9882e4` 的 positive 真实 Go 顶层已运行并 PASS，但独立 reader 及格式门仍失败，完整四模式仍未验收。新标签要求实际S2 collector签发cap、一次性Completion耐久提交、positive opaque runtime交接；另在Completion提交点注入NotCommitted／Unknown／坏readback。旧S2的75／90秒及4core门不变，新场景单独使用105秒Go／120秒外层上限。完整六包测试源显式83→84，新四标签harness不冒充普通661项必需测试。

入口提交`fdc25879c725697f8da4c030eeafd942c893a38e`的原有normal40223175556、diag40223175598、旧S2 native40223175541均成功，但新增Completion run40223175606失败。positive原ZIP 5169字节、SHA256 `f91ca6f78c8cef1bb57da3554eaaffb91a3026f068d46b4837d09f407fc37988`及实际job121259015851日志确认：SANDBOX采集在Popen前被旧apply采集器的输出名白名单拒绝，Go尚未进入；旧采集器90秒上限也不能承载新120秒场景。首次失败保留，不算Go编译失败或内核运行失败。

源码修订 `a9882e4` 为新Completion场景提供四类封闭采集器，精确匹配name／stderr／argv／sequence及30／15／30／120秒预算；沿用同一非特权环境，先取得pidfd再wait，引用不明保留pending，超时只用pidfd终止并等待5秒，不伪造exitCode。11项CPU模型实际调用新dispatcher，只替换底层Popen／pidfd等OS原语；原apply／service／旧S2采集器字节与90秒合同不变。

其实际 Completion CI `40225294759` 仍为 failure，不能用其他三条 CI 的 success 抵消。positive 原 ZIP 28625 字节／39 成员已独立核 SHA256、CRC、成员与三份关键源 Git 字节；实际 Go 顶层 10.90 秒 PASS、包 10.909 秒，四命令退出 0，attempt 为 1。reader 首拒绝为错误要求 cwd 以 `/chengwang` 结尾；正式只读挂载、sandbox cwd 断言、Popen 与 receipt 都绑定 `/tmp/mihomo-apply-source`，receipt 不是伪报。另有实际 9904 字节非空 gofmt.patch，来自新 native Completion 测试源；格式退出 0 不证明差异为空。下一最小修订保持实际 alias、精确校正 reader 并补 foreign cwd 拒绝，只转移原 Linux Go1.23 格式补丁，两个失败均保留，不靠改原件或放宽空格式门取得 PASS。root 有限审计收据 SHA256 `f682004746d80bb85ccdba2b45dd8f902abf6422185aebcc0a029704eb5cc59c`，尚不是完整 reader／四模式验收。

执行器和fresh reader各自从实际HEAD、tree、index及每项Git blob／工作树字节派生完整tracked来源；运行时manifest不把本地synthetic数量或caller摘要当authority。来源模型、整数／布尔类型、四模式字段关联、冷开及并发序列模型是CPU证据，只有下一真实Linux原件才能证明新入口运行。未提交的S2冷开按原opener转RECOVERY_UNKNOWN／PROCESS_REOPENED并增加revision，保留原执行事实；三种已COMPLETED磁盘保持原字节。Completion前后native调用前缀必须相同，随后合法cleanup尾另行验证，不把清理动作误算为Completion期间新增动作。

外部core／D协调器候选仍未集成。已发现的重试授权先后顺序及issuer关闭回收缺口正在修订；其源码冻结、MODEL或源审查结果不能算作产品恢复API、连续恢复、全部故障矩阵或生产验收。

当前接受源码`c1f9c9c05458cbd270c723f6867daf7a5c1cc936`的normal40219892631、diag40219892585、native40219892587全部成功；[c1f9聚合收据](evidence/sys06-c1f9-isolated-acceptance-20261026.json)绑定1350跟踪路径及25ZIP／442成员。root直接重数普通／race／full三套Go JSON，各1937语义、661必需全部PASS、零跳过／未完成。原语义检查函数及独立Git／原件复算、producer／fresh字节比较与旧S2四模式均通过，但不证明新的真实Completion接口或普通发布接续。

本次普通包22.668秒、race包176.367秒；single容量86.83秒、full容量55.85秒，full包116.722秒。与7a89相比各套耗时有升有降、没有受控重复实验，不把一次较短的profile包解释为因果提速或稳定余量充分；180秒／256历史／2MiB门未放宽。下面7a89和更早的接受／失败均保留为各自提交的历史证据。

实际接受源码为`7a89f8ea988fffdfdc2809210187534cd7cda1fe`：normal40216287379、diag40216287272、native40216287334均成功；[聚合收据](evidence/sys06-7a89-isolated-acceptance-20261026.json)绑定1348跟踪路径及实际Git字节。root直接重数普通／race／full三套Go JSON，各1936语义、661必需全部PASS，零失败／跳过／未完成。普通／race包18.940／138.984秒，容量5.79／67.22秒；独立single容量72.08秒、full容量86.62秒、full包177.275秒。CPU采集60.233／120.291秒完整，不代表覆盖完整六包或全部测试时间，不能相加重叠累计热点。

本次只关闭已有Completion／CurrentEpoch源码模型、四个夹具修复及旧S2四模式的隔离回归。完整私有WAL独立复算、从本批artifact重新复验候选gzip原字节、真实Completion到新head交接、恢复API、后续普通写、第二次恢复、全网业务与生产均未由此证明。本机复算使用原语义检查函数及单独Git绑定，部分平台文件身份／POSIX路径读取适配明确记录，不冒称本机运行了完整Linux CLI。9dd更早的已接受范围与全部失败历史继续保留。

c1f9有限性能修订将同一Completion调用的严格checkpoint前像重构保留一次：Completion publication slot必须走专用transition，同时匹配base raw和cap canonical；不允许generic OR分支兜底。最终freshness、取消、CAS、来源custody、一次性消耗及失败poison门保留。其编译、Go模型及旧S2隔离回归已由c1f9关闭，真实Completion与稳定性能结论仍未成立。

在9dd基线上，单一集成者已将21个Go源码文件的候选合入隔离开发工作区，并逐文件核对来源SHA256及diff检查。代码包含Execution/v3完成来源检查点、Plan/v2的后续epoch来源、完成权限及一次性交接、保留完整V3状态的普通发布适配、冷开只读诊断和按一次解码隔离的历史校验memo。这里的“合入工作区”不表示已提交、CI通过、产品流程可用或已部署。

独立源码审查已要求修复内部对象复制后的接收者绑定、时钟回退毒化、全局历史／观察预算及反向深拷贝；修订候选已合入。另查出首个Completion草稿提前使用持久记录版本校验而必拒，以及同一验证来源缺少一次性签发限制，已合入专用publication前像与custody一次性claim的源码修订，待实际Linux回归。原始拒绝报告保持，不改判为通过。封闭clone的固定摘要只接受隔离Linux实际Go反射的精确结果，不推算新摘要或通过取消检查接受新增结构。

本机独立复跑仅完成旧版来源／CPU基线和连续恢复验收器MODEL测试，不是Go编译、旧二进制对照、真实Completion或真实API证据。开发提交2b80bc97cd183c9f2a6daef080927792a044ff31的首次三套CI均失败：normal历史539项扣减错误在Go前终止，diag与native因两处局部变量遮蔽产生6个编译错误，未进入mihomodeploy测试函数体。历史扣减、两个标识符及实际14273字节格式补丁已在779f7965bacf3c0b4e48479b0bd7ed72830444d0修订；原失败不改判。

779f的实际Linux运行normal40212907145、diag40212907186、native40212907116仍整体失败，但已成功编译并执行测试。普通、race和full capacity三套原始Go JSON均显示661项必需顶层中565通过、96失败；实际结构诊断三路相同：摘要`6b46cd85d6dca689a7f40c08756671030e36722f185649540eaed875d9d07bd3`、59结构、432字段、82可变槽（64指针／18切片）。旧摘要及56／79固定门是已确定的首个阻断：它拒绝verifiedBase所需的trusted clone，也使native在获取恢复owner时提前失败。不能据此断言96项失败均无第二缺陷。本轮按这些原件精确更新固定门，并保留全部深拷贝与逐槽测试；仍须新提交全量重跑。

同次foundation的134文件格式门有4路径非空差异（11395字节，SHA256 `f04ac456b27184654fc3538b44f58c25b378b4012500e3c266b023dd8ce76a9d`）；capacity选定10文件和native选定18文件格式为空，不覆盖完整格式门。只转移实际Go1.23.12的补丁，并检查词法／字面量／注释及有限分号差异；没有本机运行Go或gofmt。原始artifact、Go事件、失败判定及完整1346项Git跟踪路径绑定均保留。当前修订是源码修复，不是新的运行接受。

944a4b94e30ad3805269f1a3ae41709602fa5436的结构门和完整格式差异已在实际Linux消除，但normal40214747262和diag40214747218仍失败。普通661项必需中657通过、4失败，零未启动；race为546通过、4失败、1未完成、110未启动，包180.040秒超时。4项失败均来自CurrentEpoch MODEL夹具使用只有演进记录、尚无Recovery的种子；当前只将该夹具改为已计划恢复的纯内存MODEL种子，保留接收者绑定、时钟毒化、全局观察容量和历史尾配对断言，不更改产品判定。

实际single与full容量诊断分别180.028／180.042秒超时，容量用例未完成；60.191／120.288秒CPU采集有效及producer／fresh成功，仅说明失败诊断可复核。采样涉及source context、legacy decode及candidate validation，累计时间相互包含，不能相加或称作唯一根因。源码已确认每次完整V3验证先严格解SourceV2，之后每条v1历史又重复解同一来源。本次有限候选只在这一次验证内复用已解出的v1 context，仍逐计划验证全部字段／摘要，v2仍重建自己的checkpoint；不共享跨操作cache，不改256历史、2MiB或180秒预算。性能是否恢复必须由下一实际Linux普通／race与原容量用例证明。

同提交native40214747219的四种旧S2模式已由原始9ZIP／192成员独立复核：真实新旧owned内核、S2耐久结果与三种固定发布故障、五端口拒绝及资源关闭均满足原合同，producer／fresh逐字节一致。独立收据`AUDIT-RECEIPT-FINAL.json` SHA256 `9fda43aa45a99f41fa13927daae5664b8c092942d8c7ac6822c376abf24fbcdb`只接受旧S2范围，不证明Completion、新head、产品恢复API、后续普通发布、第二恢复或生产。加上normal／diag，已保管24ZIP／440成员，精确源码1347跟踪路径／1346唯一Git blob；原失败及首次root辅助审计的重复candidate报告匹配错误均保留，不改判为完整接受。

正常服务协调器换绑、恢复API、普通发布接续和第二次恢复尚未闭环。外部D候选经独立审查明确拒绝：service/store锁反序、未启动撤销后的入口丢失、物理执行失败后无合法接续协议、成功POST错误声明状态未变。D尚未集成；不得用清空失败事实、伪造普通facade或把UNKNOWN改成成功掩盖这些缺口。真实Linux首Completion验收入口与失败后重新授权合同仍在开发。生产设备、主分支及Registry未改动。

计数说明：9dd原收据中的“1334Gitblob”是逐跟踪路径验证的1334项；实际唯一Git blob散列为1333。原件与原判定保留。

### 9dd同提交真实验收：持久S2与三类固定发布故障，完成提交与产品流程仍缺

9dd6313b55e29e6e5fbe4def5311b8adb4ec2751的normal40196529913实际13门success，24cb8647核12ZIP208成员／1334Gitblob／131来源／49必需测试源／125格式输入，普通与race各1884语义／635必需含新持久8及全部历史子集均过，格式差异0。原C.verify实际PASS的17600B SHAa692a5149c9b787d3b0b67ab0d58b9bae2629814c26766a0c5452cb258b03564与producer／fresh逐字同；Windows原CLI仍仅POSIXwriter拒exit1，未改函数、输入、Path或平台，不能称本机完整LinuxCLI接受。

diag40196529953实际5门success，e579c3d9核4ZIP42成员、131／49／78与635全部实际PASS。full采样120.220891650秒TIMER、容量66.68秒／包135.978秒；single实际53.546417759秒M_RUN_RETURNED、容量53.41秒／包54.57秒，未采满60秒。原180秒限制、pprof符号warning与非独立数值归因边界保持，不以不同轮次耗时变化声称已证明性能优化。

native40196529934实际10门success，f30e3ea8核9ZIP192成员／169来源／每mode33公件／1334blob，四种模式分别经过原strict reader及各自producer／fresh逐字复核。正常write／forward／post-read／injected-read为1／1／1／0，内存与盘revision18、receipt存在且adopt；NotCommitted为1／0／0／0，内存与盘17、receipt不存在；Unknown为1／1／0／0、坏readback为1／1／1／1，两者内存17／盘18且receipt实际存在。三个故障实例均poison且不adopt，原cap已消费，重放拒绝；不是把未签发DTO前门拒绝当作到达故障点。

四模式均核原8GET／真实本地marker、collection-only的S1字节与物理事件前缀不变、40字段脱敏记录投影、9个WAL检查点，按mode冷开UNKNOWN revision18或19且不恢复能力，五口拒连及三fixture清理通过。四原始报告分别28082／28093／28080／28082B，完整SHA在接受JSON中，原数据sourceGit false与经实际Git检查后的比较副本true分列；native9源格式0不能代normal125，后者已另核为0。

三套总25ZIP442成员，root聚合PID11348exit0；[evidence/sys06-9dd-durable-s2-four-mode-acceptance-20261025.json](evidence/sys06-9dd-durable-s2-four-mode-acceptance-20261025.json)待下一真实源码统一归档，不为文档单独触发运行。这里只接受隔离POSIX场景内持久事实及三种固定发布故障；完整私有WAL／Receipt公开独立复算、真实掉电耐久、完整故障矩阵、Completion／新head、产品恢复API、后续普通发布、第二恢复、互联网业务和全系统／生产均未完成。此前3dc写名单及格式FAIL不改判，生产／main／Registry未动。

### caa同提交真实验收：控制面与本地代理marker，完整恢复尚未闭环

caa58f24ec5aa0eacbb1064be3dfe2d36b2b9f4f的normal40190323838实际13门success，49e47c28核12ZIP208成员／1328Gitblob／128来源／47必需测试源／122格式输入；普通与race各1797语义／627必需含marker8及旧619全历史子集均过，格式补丁0。原C.verify返回PASS的17179B报告SHA05bc64fe7ca270bf29b3a7e6a67decc44daffb1bcb8b983786f7411368064800与producer／fresh逐字同；原Windows main仍POSIXwriter自然exit1，不称Windows完整LinuxCLI通过。其他四范围与candidate原检查器均按本提交通过，sourceGit标志比较副本与原pure flag分列，未改原函数。

diag40190323767实际5门success，07bdc7da核4ZIP42成员、128／47／76来源及627全部PASS无skip／未完／未启动。full实际99.615426892秒M_RUN_RETURNED、容量50.49秒／包100.642秒；120秒只是上限，不能冒称采满。single实际60.204115250秒TIMER、容量65.05秒／包66.073秒；pprof原符号warning、非独立数值归因及原Windows严格边界保持。

native40190323755实际4门success，48508dd1核3ZIP53成员／166来源／32公件／1328blob。真实Go top7.57秒、包7.578秒，native9源格式0；原strict reader核两轮8GET及UUID／投影、真实B路径三份101B正文同摘要、A计数3→3／B四项1→2／origin请求4→5及拒绝计数0，fixture复制、一用／重放／重采拒绝通过，S1磁盘字节及物理事件前缀不变。五口拒连、三fixture关闭、WAL8及reopen18 UNKNOWN齐；27005B producer／fresh报告SHA775bda147dfa154ca438cf44843946ee905a3cbb2c027fa6167770bdc386e051逐字同。

三套19ZIP303成员已独立保管，root聚合PID5176exit0及[evidence/sys06-caa-s2-local-marker-acceptance-20261025.json](evidence/sys06-caa-s2-local-marker-acceptance-20261025.json)随下一真实源码统一归档。这里只关闭当前来源、时效、单次控制面观测与隔离回环路径；独立原始nonce／完整私有WAL、完整故障矩阵、互联网业务、持久S2回执、Completion、新head、产品恢复API、后续普通写、第二恢复及全系统／生产均未完成。原37f与全部历史FAIL不改判，生产／main／Registry未动。

### 3dc实际结果：635普通与race通过，格式和私有证据写入接线失败

3dc40e5f207f5f23966ad2eb461cb199c23b6c2b的normal40194798491实际11成功／2失败。4f3a9ef7核11ZIP206成员／1333Gitblob，普通和race各1884语义／635必需及全部旧集合全过，stderr空、Go退出0；真实格式差异17962B SHA54332da63a0d7866428646a88e7b167cc4a690fb04f9ab331b7d758b0fc3aab2非空，严格格式门FAIL，没有foundation producer／fresh接受。diag40194798548实际5门success，913f2788核4ZIP42成员及635全过；full采样120.315912883秒TIMER，容量85.44秒／包171.917秒，距原180秒仅约8秒；single60.152306842秒TIMER、容量65.59秒／包66.614秒。耗时仅本次观测，不当作已证明的性能根因，不放宽预算。

native40194798493实际10门中2成功／8失败，aa30aea3核5ZIP180成员／169来源／1333blob；四模式均真实进入top，positive10.17秒、not-committed9.23秒、unknown10.21秒、readback8.29秒，均在post-attempt checkpoint处失败，四份格式差异6142B完全一致。固定源码中的已签发能力、record返回、精确replace／readback计数及poison／不adopt断言在该失败行之前，不能把这个到达证据升格为完整回执、检查点或冷开通过。只有32／33公件，缺record投影，四份fresh未生成；原reader对部分原件自然拒绝，保留失败，不用diag或普通Go成功抵消。

已确认接缝是原labNativeRecoveryWrite的封闭文件名名单遗漏verification-attempted-control.private.json及verification-record.private.json。修订只新增这两个确切名字，原12名顺序及0600、O_EXCL、O_NOFOLLOW、固定目录／owner、fsync和2MiB门全保。另只转交本轮实际6源12hunk格式差异，逐Git前像、位置、有限Go1.23词法／可省分号护栏及独立后像核对；四native补丁与normal的native-test子段逐字相同，不以9源native格式代125源normal格式。源码修订不改业务字段、模式、权限、635名单或工作流；新的同提交普通／race／格式及四模式完整原件验收仍待，旧失败不改判。

### 当前源码：Execution/v2持久S2回执，四种原生场景完整验收仍待修订后证明

本轮新增一次性记录能力，只能由原collector成功消费真实观察证据后、在当前来源与权限短锁内签发；它绑定原证据指针、collector、store、磁盘、owner、S1完整canonical及调用方／服务context。原证据与记录能力均按原指针先消费、后作其他拒绝，不能由DTO、JSON、散列或通用publisher重造。磁盘记录阶段只持store锁，保持原CAS／fsync／精确回读与封闭发布入口；写入异常后毒化实例并撤销live／retained证明，不重发或重采同source。此前事实晚到最多记为RECOVERY_UNKNOWN，不代表记录瞬间仍有跨库原子权限，也不提供新物理动作许可。

Execution/v1原9字段及nil新指针时的旧编码保持，末尾新增可省略Verification，仅execution/v2接受完整typed回执。v1带回执、v2缺回执、未知版本／字段、错误长度或nil切片都必须拒绝；两个内存数组显式转换为长度2和8的typed切片，未引入RawJSON或泛化Array回退。严格验证会恢复完整S1前像的版本、revision／hash、owner／fence、时钟、transaction时间及失败观察前缀，并运行原v1严格解码；原armed前像另行保留。旧二进制不能读取新v2数据，不允许通过删回执冒充安全回滚。

封闭trusted clone已按实际类型扩为56结构／412字段／112类型节点、79可变字段槽，新增8个显式深拷贝方法；在物理Stop／Start之前容量预留包括完整S2事实及active／archive最坏封装，仍保2MiB、256历史、普通180秒以及每个native场景75／90秒、4core边界。Current、head、Completion和产品恢复API均不推进或开放，重开只保留事实并保持UNKNOWN，不能恢复内存能力。

normal已接131来源／49必需测试源／125格式输入，必需声明635，名单SHA256为1be6eaf9abe7f03253410f6db950935f33162a30deee033c6cd401666ade36d6，旧627／619及全部历史集合精确保留。检查器187项CPU模型当前通过，PID40524；首轮tvqk7__f实际1fail／4error源于独立兼容来源镜像漏新3Go路径，已仅补显式来源数据行并保留原失败，未放宽判据。A的实际decoded工作流和11个破坏反例、B的typed边界与56结构图及源码同行都是有限源码／CPU证据，不代Go或真实持久化。

native正在接正常append、NotCommitted、Unknown和坏readback四种封闭模式，各用独立CI进程／namespace及独立原件与fresh；真实已签发cap、到达replace／回读的计数、失败后不adopt／不重试及冷开事实均须分别证明。普通bounds不使用未发行DTO在前门被拒绝来冒充已到写入故障点；当前四模式仍属待完成的新验收，不借caa已接受的本地路径代证。

### 历史37f实际编译失败：本地marker无用导入与普通格式失败

37f4aa5e3b5834b6de671a297561e5734bea99f2为27文件统一源码集成，精确1327Gitblob。normal40189516666实际3成功／10失败，diag40189516609实际failure，native40189516618实际2成功／2失败；三路实际stderr均指出lab_recovery_marker.go第5行encoding/json导入未使用。full诊断与normal普通／race的122B stderr SHA2788975128e8bf925da9032ea8bc44d3166ad6594d85536d78d70e2f7ddd4c84。其余包确有153项必需测试通过，但mihomodeploy编译失败，474项未启动，含新增marker8及容量用例；没有新的marker／原生清理或数据面运行接受。CPU模型与源码同行检查没有覆盖编译器的未使用导入约束，不能把它们称作编译通过。

normal实际格式补丁6994B SHA9be179f2fa695a36e0f80245d58076c5226a2c2ebc4ab629f0b11c91ad73e748，虽formatExit0但严格门仍FAIL；诊断的格式补丁为空和native9源格式0不能代normal122源。修订只转交本轮真实4源5hunk，逐实际Git前像／位置／摘要和已核有限Go1.23词法／分号护栏检查，独立重建后像；这是机械格式转交，不是本机gofmt执行、Go AST或任意语义证明。原格式FAIL保留，新提交仍须实际格式0证明。

逻辑修订仅删除该import，与上述机械格式独立绑定；未格式化的单行修订源码SHA为e763b775e8f0fbe81fd78b9c1aaf197d3854f621ea25104e630d115c5ec3300e，最终源码摘要由本次集成证据逐文件记录。接口、627名单、时限、权限与校验门不变。原37f失败保留，修订的Go／race／格式／原生真实链必须重新按同提交CI验收，不能移用007或CPU结果。

### 本轮源码集成：恢复后本地代理marker，真实Linux验收待修订后重做

源码增加原服务fixture来源封条及原指针有界登记、实际本地代理路径的一用receipt、三份完整正文／现场摘要和A、B、origin有序计数交叉检查；未签发、复制、跨fixture、关闭、取消及重放均须拒绝。采集同时绑定调用方和原服务生命周期，沿用最早截止时间，操作前后复核授权；这不是可硬中断所有系统IO或无撤销竞态的证明。13字段marker只证明隔离回环路径，origin记录完整Write结果，不能称origin EOF；原八GET、S1磁盘状态、物理事件前缀、五口清理和重开约束仍保留。

普通源码128／必需测试源47／格式输入122，必执行顶层声明627，名单SHA256为3bd65c00bb45bbef41763cadf7b8b98c6c0ce2fbc8ec93b3bb8dfa6dd0880543，旧619和全部历史名单保持精确子集。native绑定166来源、32公件，诊断仍为120秒／60秒原上限。本轮187项检查器CPU模型通过，native两个受影响模型及35个marker否定子例和实际工作流声明脚本的11个破坏反例已作有限CPU核验；这些均不代替新Go、race、gofmt或原生运行结果。

Control readback的DataplaneProven继续false，localProxyMarkerProven不能升格为互联网或业务可用。完整故障矩阵、持久恢复回执、Completion、新head、产品恢复API、后续普通写与第二次恢复仍未完成；持久Execution／Current／head不扩张，生产、main及Registry未动。

### 007三套同提交实际接受：S2真实新内核控制面观察切片收口，完整产品未完成

00759ce2f24335036c0dcfd264b15ccde2c424a0的normal40186217123实际13success，原件closeout0e5d2b64核12ZIP208成员／1322Gitblob／125来源／45必需测试源／119格式输入，普通和race各1538语义／619必需及原全部历史子集全过，format0。原C.verify实际返回PASS的16790B报告d50e84f5与producer／fresh逐字同；原Windows main仍在POSIXwriter自然exit1，明确不是本机LinuxCLI接受，没有修改函数／输入／Path／平台。

diag40186217124实际5success，独立f650eccd核4ZIP42成员、125／45／74及619全部通过；full120.230643829秒TIMER，single53.844585481秒M_RUN_RETURNED，后者未采满60秒不能冒称满窗。容量65.52／包128.832秒仅本次观测，原pprof符号warning及数值非独立归因边界保留。native40186217126实际4success，独立9e76ab34核3ZIP52成员／163来源／31公件，Go9.91及native9源格式0；原strict reader完整核新core两轮8GET原文及UUID／投影／时间窗、S1rev17／当前源、复制Started／proof和一用消费／重放／重采拒绝、S1字节与物理事件前缀不变，原5口／3fixture／WAL8／reopen18／10checkpoint齐。26045B producer／fresh逐字同SHA5ee3c259433ccf1006362b6e70784339ef90f06fb7687693de0c5a58353cebbe。

其他service／apply／compat／candidate／UNKNOWN原函数亦按本提交独立通过，总收据b8fe17da，副本sourceGit标志比较和原pure false分列，不改原报告。三套共19ZIP302成员，接受档[evidence/sys06-007-s2-control-observation-acceptance-20261025.json](evidence/sys06-007-s2-control-observation-acceptance-20261025.json)随本轮真实源码统一归档，不为文档单独重跑。这里只接受当前来源绑定、时效和一用证明下的控制面观察；完整真实故障矩阵、恢复数据面／持久receipt／completion／新head／产品恢复API／后续普通写／第二恢复与整套系统和生产均未完成，旧UNKNOWN及所有失败保持。

### 785实际619普通／race和两套限定运行接受，119源格式差异仍使normal失败

7850204559b8722e9c8c11f63fcbe8e9e9fa1a9d修正了实际workflow漏接名单。normal40184766297真正执行普通／race，各1538语义／619必需全PASS，无skip；独立事件审计35136exit0、fe33b7dc核125来源／45必需测试文件／119格式输入和全部旧集合／旧79与81测试body。三个工具退出均0，但真实gofmt产生25177B原补丁SHA2fd0fc54839d685e79d1d329b7baf1e53252dcee6f1d612d5602099cdbdda4b2，严格格式门拒绝；原完整C.verify与foundation fresh没有PASS报告，whole normal保持11success／2failure。容量7.5／87.19秒只是本次观测。

同提交diag40184766181五job success，独立e7df61d2核4ZIP42成员／1320blob／125来源／45必需／74实际测试源／619全部过，producer／fresh逐字同；full120.297764816秒和single60.170917940秒均TIMER，容量85.62／包165.901秒。native40184766176四job success，独立4897fbf6核3ZIP52成员／163来源／31公件，Go10.06及其9源格式0，新core8GET、四类copy／once／recollect拒绝、S1／物理prefix不变和全部原清理／WAL／reopen约束均过；26045B producer／fresh同SHA3a0087491aa6410fd3d48dee4a6c7eb1c150830a0037b25c80b51e75df1ab773。native9源格式0不能代normal119源；其余五原门11c17656／21d98488也独立通过，18ZIP300成员完整保管。

原raw-token格式转交器PID29520严格拒绝：官方gofmt把可省略显式分号改成换行，旧regex未表达Go自动分号规则，不能据此声称程序逻辑有差异或原token门通过。原拒绝保留；后续只在新外部辅助版本中核固定Go1.23.12官方分号规则及有限词法，仍必须完整Git／hunk前像／原artifact摘要、注释／literal／operator保全及下一实际CI，不能泛删for头分号或关闭产品校验。完整档案见[evidence/sys06-785-s2-normal-format-failure-20261025.json](evidence/sys06-785-s2-normal-format-failure-20261025.json)。真实故障矩阵、恢复数据面、持久receipt／completion／newhead／API和全系统／生产仍未完成。

原格式补丁的严格转交随后实际成功：新外部helper PID39804exit0，10c92b5c收据只含3个Go源的23个真实hunk，119源允许表／Git HEAD-tree-index／每个前像与位置／原25177B摘要均核；B在读取A输出前独立重建同样三个after，adf20612源审及逐字hash一致。新辅助guard依据固定[Go1.23.12规范](https://github.com/golang/go/blob/go1.23.12/doc/go_spec.html#L166-L209)与[官方scanner](https://github.com/golang/go/blob/go1.23.12/src/go/scanner/scanner.go)，保for头分号、operator最大吞并、comment／literal原文，仅规范自动／可省略的语句分号；9正21负CPU例实际通过并独立读回。只authority的旧raw-token比较仍为false，旧拒绝不改判。该有限词法检查不是Go AST或任意程序语义证明，也不独立证明编译器directive位置语义；实际可信gofmt来源／精确hunks与下一Go编译及原格式门仍是必需证据。root已应用三个精确after，未在本机运行Go／gofmt，下一同提交CI仍待。

### 66c真实S2控制面限定接受；普通入口旧名单拒绝，精准修订待新CI

66c5210f55dd9a3f9edd34a85c40d5fff6302d6f的native40183908514四门成功并独立3e567c3e接受：Go8.78秒、该native格式范围0差异，163来源／31公件／3ZIP52成员。实际新core两轮八GET正文／transcript／headers／EOF／close／hash与投影及UUID重算通过，S1 revision17／身份／Started30秒上界、真实复制Started与proof拒绝／一用重放及新collector重采拒绝、WAL字节和物理事件prefix14→14不变；原五口拒连／三fixture／WAL8／reopen18／10checkpoint完整。26045B producer／fresh逐字同，SHA54eb49594299df94238ad37c267cd40869036f246882caa72564567385d4c3d3。ObservedAt仅读回采样时刻，不冒称最终准入或消费时间已公开独立复算。

diag40183908402五门成功，独立66526cb7核4ZIP42成员、1318Gitblob及125来源／45必需测试文件／74实际包测试源，619含新8及旧611全部实际通过，无skip／未完／未启动；full120.261947162秒与single60.240934253秒均TIMER。容量79.54秒／整包155.521秒只是这次观测。pprof符号warning及原WindowsCLI／POSIXwriter限制保留，sourceGitVerified比较副本和原pure false分列，不改输入或原函数。

normal40183908390终态11成功／2失败：47消费模型和25证据模型原log都OK，但workflow漏同步新8，旧previous607由619减4得到615，严格拒绝；后续普通／race合同Go及gofmt步骤为skipped，不能说它们通过。原foundation仅两个模型log，无Go事件、格式补丁或fresh报告。其余service／apply／compat／candidate四原门及UNKNOWN由原函数和producer／fresh独立通过，44bccb0c／81c0ad7b收据仍保wholeCI failure。三套合计18ZIP289成员。完整档案见[evidence/sys06-66c-s2-native-acceptance-normal-wrapper-failure-20261025.json](evidence/sys06-66c-s2-native-acceptance-normal-wrapper-failure-20261025.json)。

精准修订只更新该workflow的显式新8、旧611327f及607／591／587／585／539／528／407保留链和总619pin8a2587，13jobs／权限／分支／命令／180秒不变。A原heredoc原log实际18172exit1重现旧拒绝、新38956exit0通过，11个缺源／改名变体均拒；独立0bc7b31c核严格逆转及YAML外围同。该修订是CPU与源码结果，必须新提交真实普通／race／格式，不能挪用66c诊断或native作完整正常接受。真实完整故障矩阵、恢复数据面／持久验证回执／完成许可／新head／产品API及全系统／生产均未完成。

### S2当前开发：真实样本时间接口与私有新内核验证采集

新增只读SampleTimes接口从原opaque双样本返回四个真实采样时间值，独立校验形状、摘要和时间顺序，不把时间DTO当授权、当前新鲜度或业务可用性。对应三项Go测试声明已汇入开发目录，但尚未执行Go。私有post-S1来源绑定、VERIFY当前授权、八GET捕获与一次性观测证据由实现代理开发，独立代理审阅；来源发行只能发生在原Started能力真实消费及S1磁盘提交／读回成功之后，不能用旧q或JSON重造。持久Execution-v1、Current及head不扩张，后续数据面、持久验证回执、完成许可和产品API仍须实施。

检查器source／formatter／mandatory名单已为新增四源接线，normal125、compat136、apply144、service151、unknown157源仍逐项绑定且不删除旧源。五类检查器187项纯CPU模型通过，实际PID14728，原件位于D:/CodexData/workspace/s2-source-models-ikzoh5s2；首次来源数量未同步的失败oz5il9db原件保留。该CPU结果不证明Go编译、格式、真实HTTP、新内核观测或生产。源码冻结时尚未统一提交／Linux CI／原生验收，后续实际范围以上方66c同提交收据为准。

### 2026-10-25 b57三套原件接受：真实native Started/S1事实/清理/重开本范围闭环

b57d57eb2546874fc4ae8a90e8992ab1ea72f841同提交正常40179752807实际13success，root f00bff1b核12ZIP208成员／1312blob、普通与race各1503语义／611必需全PASS及format0，原C.verify16274B报告f9db9469与producer/fresh同。diag40179752897实际5success，独立f97f29ba核4ZIP42成员／121/43/72来源及611全部PASS，full120.271824712秒TIMER、single60.229660250秒TIMER；容量79.44／包154.557秒只是本轮观测。原Windows CLI/POSIXwriter exit1仍单列，不冒充本机Linux写入接受。

native40179752888实际4success，独立eb96506b核3ZIP42成员／159来源／21公件／16实际模型，GoPASS8.22秒、fmt0；原verify_raw全部严格门通过，实际五次拒连、三fixture Shutdown/Serve、八阶段WAL index、reopen18 RECOVERY_UNKNOWN和十checkpoint完整，未削弱时间窗或阶段校验。Linux producer/fresh23753B逐字同，SHA df43c5da2ab98161f9fce6aa4b739b0b4581473b4d12d92b839c84d30b7c359e。原pure-data结果的sourceGitVerified仍false，仅显式comparison副本将已独立核验的source标志设true后比Linux两报告，不改输入、函数、权限或平台。全部三套19ZIP292成员保管稳定，前三轮native失败及外部审计器错误记录仍按原判保留。

此接受只证明隔离实验内实际UNKNOWN→独立批准→实际Stop/Start→S1事实磁盘入库→重放拒绝→两代及fixture清理→五口拒连→严格重开失效封闭。完整私有WAL公开独立证明、全系统syscall tracing、S2/data-plane/完成permit/新head/产品恢复API/后续普通写/第二恢复/互联网业务和生产均未证明，标志保持false或未知。接受档[evidence/sys06-b57-native-started-s1-acceptance-20261025.json](evidence/sys06-b57-native-started-s1-acceptance-20261025.json)已写，待下一真实源码统一集成，不为文档单独触发重跑；生产/main/Registry未动。

### 2026-10-25 db原生Go通过但独立reader拒绝；时间快照与WAL阶段修订待新CI

db4253778987aa4ba8a83a6ec871921a23f3439f正常40178390753实际13success，独立def81fb5核12ZIP208成员／1310blob与1503语义／611必需各两模式全过、format0，原C.verify的16274B报告f668f9be与producer/fresh同；原Windows main仍在POSIXwriter边界exit1，不作本机LinuxCLI接受。diag40178390620实际5success，独立9ea364d0核4ZIP42及121／43／72／611，full120.313207556秒TIMER、single54.341532049秒自然早返，不能把single称采满60秒。

native40178390657实际Go top PASS8.31秒、fmt0、attempt.exit0，三fixture关闭、五真实拒连、S1 Started及严格reopen18均有原件；但原whole reader及fresh仍FAIL，完整失败档为[evidence/sys06-db-native-reader-rejection-20261025.json](evidence/sys06-db-native-reader-rejection-20261025.json)，不得把Go成功等同独立接受。独立946dc4b0保2ZIP38成员、21公件、159来源与十个checkpoint，原时间窗口首拒及WAL组件阶段拒绝保留。

实际两个primitive把StartedAt取为可变now地址，后续重赋now覆盖它，导致StartedAt和ReturnedAt同值而真实dispatch在之前。修订仅两个源各将开始／返回时间保存为独立快照，保持采样点、now刷新、失败closure、权限／有效期／caps／原生调用次数及reader严格时间窗口。reader另只把WAL阶段常量对齐原store的OLD_EPOCH_QUIESCED；观测结果QUIESCED是不同域，原样保留，新增协调篡改report/index为旧literal的拒绝反例。两受影响模型通过，16名字／159来源／21公件不变，旧raw不适配。

作者789a0a8d／27fb2f94与独立04722e08为四源必要审阅；351个internal Go源的同类指针有界文本／人工检查32773978未发现其他确定同类问题，不等于编译器全程序别名证明。尚未执行本机Go/worker/native或调整机器时间，修复效果必须由新Linux原件、原reader与fresh证明；生产未动，完整S2／产品恢复API及系统闭环仍未完成。

### 2026-10-25 133底座双套接受、native清理探测失败；v2五端口实际观测候选

133ef0ab1522f182486e5c3d7d377aab76e0fa70正常40177100131为13门success，独立8165eb68核12ZIP208成员／1308blob，普通及race各1503语义／611必需全部PASS、format0；原C.verify返回16274B报告128733f0与producer/fresh字节一致，Windows原main仍在未改POSIXwriter边界exit1，不称本机LinuxCLI通过。diag40177100066五门success，独立624c2d5e核4ZIP42成员／121/43/72及611全过，full实际120.286819940秒TIMER、容量83.67秒、包162.437秒；不推长期性能。以上不能覆盖native失败。

native40177100093已实际越过独立批准、Stop/Start与Started17，重放不增加调用，两代退出及清理有原件；但唯一top7.33秒在五端口检查失败，closedPorts只记录28411/12、reopen未到，整体FAIL。两ZIP38成员、21公件、sandbox serviceBases本轮原组件已通过，缺fresh原判保留。故障源码定位为调用方误用仅准两端口的labQuiescenceDial：28413入口直接OTHER／Attempted=false，不能据此声称仍有监听。fixture真实owner是Go labLocalFixture，原service.Close已有Shutdown/Serve join；不引入先前未证实的Python worker关闭协议。失败档见[evidence/sys06-133-native-cleanup-failure-20261025.json](evidence/sys06-133-native-cleanup-failure-20261025.json)。

新候选保留原两端口quiescence门与fixture/service/store/authority源，新native-only helper只准固定五个loopback tcp4端口并实际DialContext；探测先保存Attempted/Result再判失败。原fixtureCleanup观察来自真实retained owner，和五份cleanupProbes一起公开；closedPorts仍要求全部五口，严格reopen及十个checkpoint仍保留。report/contract显式升级v2，PUBLIC21／FILES159／16模型名字不变；独立reader严格三role shutdown/join及五次真实拒连，14个新增负例与合法forced-close非零正控已通过模型。作者046cb28f/B e5c641a6与独立peer f7856a61只证明源码／模型，不代表native已成功；必须新CI。未运行本机Go/worker/native，未改变生产。

### 2026-10-25 cde首次真实native失败与caller／producer修订：必须再做新CI

cde91493ba5f155a9d5da0367edd53046aa86274统一28文件后，三套CI均实际运行。normal40175135231为11成功／2失败：普通及race各1503语义／611必需全过、Go均exit0，但实际9609B gofmt差异使正常合同失败，fresh报告缺失。独立normal9aa0ac00核11ZIP206成员／1306blob；原其他五scope门及producer/fresh各自通过，不能覆盖normal失败。diag40175135226五门success，独立da36ff6a核4ZIP42成员及121／43／72来源与611全部通过，full容量50.91秒／包101.448秒、采样100.423806204秒M_RUN_RETURNED，不声称120秒。

native40175135319实际两成功／两失败：Go编译并执行唯一top后6.29秒FAIL，报告仅到PLANNED rev12且selfApprovalDenied=true，恢复Stop／Start尚未调用；bootstrap启动和失败清理另有真实OS观测。独立05dc3820保2ZIP38成员、19／21件public（缺两份new-kernel流）与缺fresh原判。原sandbox组件因缺serviceBases严格拒绝，未往旧raw补字段。CLI因public不完整在writer前拒绝，不伪称本机Linux写入成功。完整失败档见[evidence/sys06-cde-native-first-failure-20261025.json](evidence/sys06-cde-native-first-failure-20261025.json)。

源码确认caller分别取两次当前时间，和recordRecoveryApproval要求IssuedAt.Equal(now)冲突；这足以构成必要修复，但现有原件没有区分独立批准与入库子步，不能称唯一运行根因已证实。修订仅一次真实approvalAt供两个原API；额外当前freshness只读context、墙钟、实际owner及到期信息，不调用trustedNow/token/verify、不写LastTrustedAt、不替代后续Stop／Start现时授权，也不提供跨调用原子性。现有FailureCode增加封闭阶段诊断、不输出rawerr；成功仍PASS／NONE。producer仅在a.sandbox、s.bases(False)、native_base(False)实际通过后公开三条真实serviceBases。原store／RBAC／caps／strictreader均不改。作者45ef688b与独立peer46c7117e仅证明源码修订，未Go/native。

三份Go空白由本次实际normal及native formatter原件独立迁移：raw patch哈希ec85df85与d92bea0b因文件顺序不同，3份postimage严格相同，3hunk位置／原Gitblob／保守词法token均核；迁移收据58a117b4与c40263f1。root将此格式修订与最小caller／producer修订合并再提交验收，未运行本机Go/gofmt、未放宽180秒／256历史／2MiB或任何权限检查，未改判旧失败。S1真实入库、S2及产品恢复闭环仍须后续实际证明，生产未动。

### 2026-10-25 原生Started事实实验与独立reader：25源组装，实际Linux验收待证

本轮将原生v3的11源、默认控制绑定10源、专用CI两源及独立reader两源共25源汇入开发工作区。v3修复Wait事件观测同步、双owner close持续拒绝和成功前末端context复查；仅最后一项是逻辑deadline检查，不能强制中断同步OS读取。root对native测试只删除最后一个多余LF，保持全部其他字节，并单独保留c7d7fb13→ab20fa0b的21254B→21253B修订证明；不是本机gofmt输出。

默认来源121、必需test文件43、必需611名单及旧pin均保持，格式源115；新native测试带专用tag，不伪称由默认611执行。专用工作流四任务仅固定开发分支，无paths过滤，复用真实固定内核获取、UID/caps/no-new-privs、只读模块和新net/mount/pid namespace；actor/源工件/权限/原件均保持隔离，不接生产。它尝试从原实际UNKNOWN经独立批准、旧内核quiescence、有效lifetime context启动、S1实际磁盘事实、重放拒绝和两代清理后重开；是否成功必须由新Linux CI原件证明，不能由源码或模型推导。

独立reader不导入producer，绑定159个真实路径和21件公开原件。source-before在worker要求的初始3件公开文件之外保存，attempt后无论成功失败均另取after再公开；fresh只读取既有原件，不再次启动内核。root发现并修订的提交来源问题现在要求实际commit tree、stage0 index与工作树blob三方一致，CLI还核自身来源；V发现的PID域已按原owner收紧为至少2。最终16个模型含真实Git exact/staged/unstaged负例及old/new/syntax协调PID1拒绝，实际PID14412、exit0；它们仍是reader模型及来源检查，不是native执行。私有完整WAL、S2、HTTP恢复完成、授权闭环、真实互联网业务和生产状态不由该实验独立证明，相关标志保持false或未知。

### 2026-10-25 b409的611常规与同提交诊断原件接受；native接线仍待

触发覆盖修复b409ab58ea5d061a536c19d8a29c1165070f59a8已推送／远端一致，两工作流均实际触发。正常40171643965共13门success；root独立df3ca579核12ZIP208成员／1294blob，普通及race各1503语义／611必需全过、format0，原C.verify实际返回PASS的15729B报告be9f9cf82f984be3132eba8e2fb53e26e24c1444242d8ea9e67f19668c2ae7f0与producer/fresh逐字节同。原Windows main仍因未改POSIX writer边界exit1，明确不称本机完整Linux CLI通过，未替换Path／平台／函数或AST门。同提交诊断40171644029原件独立复核仍在进行，尚不称双套接受；先前d041／ead失败原件与原判保留。

后续同提交diag40171644029已实际五门success，独立closeout72b2dd8a／atomic a6182e2c核4ZIP42成员、1294blob及117／43／full71，strict1503语义／611必需全PASS，新4 selected、16S1、bfae和全部旧必需集合实际通过；原producer/fresh字节一致。full容量85.64秒、包164.268秒，profile120.303秒TIMER；single容量87.18秒、包88.212秒，profile60.247秒。完整两套共16ZIP250成员；是本次有界验收，不推固定性能或长期可用率。接受档为[evidence/sys06-b409611-acceptance-20261025.json](evidence/sys06-b409611-acceptance-20261025.json)。

native v3的11源候选5830e9ac及独立微差分peer2e23176d已处理Wait观测同步、双owner重复拒绝和末端context检查，仅源码审通过；独立reader／专用runner／workflow及各scope真实源集合接线尚在开发，没有Go、原生实验或完整恢复接受。其现有可复用执行环境经实际源码更正为GitHub ephemeral ubuntu-24.04 runner内net/mount/pid namespace，不是Docker容器，不宣称digest-pinned执行镜像或显式cgroup硬配额。安全隔离、固定工具链／内核及资源观测各按实际原件分别证明，不以文案替代证据。

### 2026-10-25 CI触发覆盖修复：固定开发分支每次提交均运行两套验收

2b63a001f14b6cc72ddb8019cd77c2b373aa5e2f只修改新adapter测试的实际formatter空白，GitHub API仅出现正常40170650512，诊断未被触发。实际旧diagnostic paths只列lifecycle／lab_recovery_plan／bootstrap_state等，未覆盖已经纳入full suite的其他Go源；正常paths也遗漏六包中的authz。此为源码及实际触发记录支持的CI覆盖缺口，不能编造该提交的诊断运行或复用d041为新提交接受。

两workflow的push均保唯一codex/chengwang-mihomo-lifecycle-20261024分支，移除paths筛选，让该独立开发分支每次提交都纳入正常与诊断验收。workflow_dispatch、permissions、concurrency、13/5 job全部执行内容、命令、固定工具链及既有runner声明、隔离namespace、180秒/256历史/2MiB不变；不扩大main或生产写权限。改动会增加仅改文档时的开发CI开销，避免新目录或路径遗漏继续让同提交的完整验收缺席。行为依据[GitHub workflow path/branch filters](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushpull_requestpull_request_targetpathspaths-ignore)。新触发范围仍须YAML/分支约束及实际GitHub新提交运行验证，不能用源码检查当已触发。

### 2026-10-25 d041的611全部Go通过、正常仅格式失败：真实四hunk修订待新CI

d0412c7ba0c4a4fefbdb8322ca021c10eebab195正常40169669618实际11成功／2失败：普通与race各1503语义／611必需全部PASS，旧607／新4 selected-target、S1及bfae属性通过；容量7.46／86.57秒、包21.772／165.872秒，非超时。实际gofmt.patch为4664B，仅新target test的4个map对齐hunk；normal严格格式失败、foundation fresh确无报告，未调用必拒完整C.verify。root独立f23e37b9核11ZIP206成员／1291blob与117源／43test／111fmt、5scope原函数/fresh、原件及来源末次稳定；首in_progress快照与终态均保留，不重跑成功门。

诊断40169669594五门success，独立59cda664核4ZIP42成员／1291blob、117／43／71与原strict events1503／611、新4含同mapper输入pointer反例、旧607／16S1／bfae、原source/resource/namespace/argv及producer/fresh。full容量54.27秒／包106.726秒、profile实际M_RUN_RETURNED105.696秒，不声称满120；single容量85.41／包86.444、采样60.249秒。诊断tagfmt0不覆盖正常111文件，不能用diag成功抵消normal失败或承诺固定速度／长期稳定。

root仅应用实际4664B原patch c346e7deae5be75cd12ff49a2c5c7669d41cd0f893ecbe2cfe1b6bcd1617c7c3的单源4hunk，strict transfer bd5a5636ccb4cf0eccd1c41407fa701333f5839737cd66496e11a593cc330da5；原Gitblob/原hunk位置/词法token核对后，test源1a013c06→12ff191ba2a0914a97fb814729df0861ac8daed4b61ab99947b7a3fe55ae315f。原611名单、prod比较器及全部其他源、Go命令/180/256/2MiB不改，不运行本机Go/gofmt或重旧模型；新格式提交必须独立Linux CI验收，尚未获接受。native v2真实启动/所有权交接/两代cleanup、独立reader/CI、新S2 collector/receipt/completion／产品恢复接口及完整系统与生产仍未完成。

### 2026-10-25 选定目标投影比较叶子与611接线：源码集成，尚待实际Go

新增CompareLabTargetReadback仅复用原CompareLabReadback(samples,target,target)的opaque输入／摘要／8GET两样本／witness／时间顺序检查，然后在独立封闭enum中将原AMBIGUOUS解释为“选定目标投影匹配”，DRIFT/UNSTABLE仍按原义，STABLE_OLD/NEW或未知结论拒绝。旧API/enum/reader及S1存储代码不改，报告四个payload/dataplane/authorization/production标志全false，Observed摘要指针单独复制。该叶子没有绝对新鲜度／Started epoch／issuer绑定，不能作为私有恢复事实、授权或完成许可；S2 collector必须另建真实来源链。

两个Go新源四top覆盖旧==新时旧API仍AMBIGUOUS、old或new均可为显式target、drift／witness与时间不稳、请求数／摘要／expectation／零输入拒绝、封闭映射及报告独立性。root按独立review补同mapper结果直接变异其输入指针的可辨识性反例；prod9b3eb947／test1a013c06固定，source peer173aa5c1与控制peer d0b5d089分别审阅。13源码（2Go+11control）来自33606210，有限6fixture及source/AST/YAML检查不当实际Go通过。

必需611 pin327f5833d99a02a12170b894aec43da81432c85c6de78338b15532ab3572e79c，旧607／591／587／585／539／528／407完整保留；normal117源／43test／111fmt，compat128／apply136／service143／unknown149，全六包71个test来源。原双Go命令、13/5工作流其余字节、180／256／2MiB不变。真实Go／格式及新4尚待本提交隔离CI，S1 native启动入库与资源owner交接、S2 collector/receipt/completion、HTTP/facade／新head／后续及第二恢复／完整系统和生产均未完成。

### 2026-10-25 04e的S1 607结构测试完整通过：不代表真实native恢复入库

04e947eb0b4ee0cb166ad659c99a7f3ccb7fab06正常40168547039实际13门success；普通／race各1473语义／607必需全部PASS、format0，原591及新16 S1、bfae schema／48结构／68槽属性实际过，容量4.56／55.13秒、包15.426／108.809秒。原C.verify实际返回PASS，15472B报告c144e410…2b0f16与producer/fresh逐字一致；Windows原main随后按原POSIX writer检查exit1另列，不伪装Windows完整Linux CLI通过。基础5eac1f3f／其余scope035a9b0d核12ZIP208成员／1287blob，原件与source稳定、5scope原函数/fresh通过。

诊断40168547003实际5门success，独立8faecdfb／原子b0e9881a核4ZIP42成员、115源／42test／70全包test／607及原strict events1473／607全过、16 S1与原集合、source/resource/namespace/argv及producer/fresh字节一致。full容量86.87秒／包166.248秒，完整定时profile120.295秒；single容量49.65／pkg50.817、采样49.794秒早结束，未说满60。原180／256／2MiB未改，不据本轮耗时承诺固定速度或长期稳定。接受档见[evidence/sys06-04e-s1607-acceptance-20261025.json](evidence/sys06-04e-s1607-acceptance-20261025.json)，旧ead失败与缺fresh原封。

这里证明S1结构方法与指定旧新测试在隔离Linux实际运行通过；测试内MODEL发行和磁盘不冒充真实native Start/cap/FS落盘。有效上下文真实启动、sole-close-owner交接、双代kernel cleanup仍由下一独立native实验实现/验收；selected-target叶子、S2 collector/receipt/completion、HTTP/facade、新head、普通后续写及第二恢复、整套系统与生产仍未完成。

### 2026-10-25 ead的607全部Go通过，但正常格式失败；按真实formatter修订

ead8a40bc4ef693ea54122ce74e70ec185729ac2正常40167848337实际11成功／2失败：普通与race各1473语义／607必需完整PASS，原591及新16 S1、bfae schema／48结构／68槽、新旧UTF8反例均实际过；容量5.77／65.86秒PASS，包17.770／128.453秒结束，无超时。原gofmt进程exit0但patch7705B非空，严格格式门仍拒绝；不能把进程exit0当格式清洁或用Go通过改判normal。独立foundation b3f9f41b、其他五scope原门/fresh各自证明限定范围，原foundation fresh缺失保留。

诊断40167848304实际5门success，完整7116cf14／原子067b9a26核4ZIP42成员／1285 Git blob、115源／42test／70包test／607及old591/587/585、新16与bfae／UTF8、原source/resource/namespace/argv与producer/fresh逐字一致；full容量87.55秒／包166.889秒。诊断的tag文件fmt0不能覆盖正常109文件格式门，不据单轮结果承诺长期稳定或native恢复成功。

root仅转入实际7705B原patch的3源10hunk（v3／Started／Started Linux test），原patch SHA0a327bf974e4b147c94c4de4baefddc9cf0c129e572bd45936c6df56630ac000，transfer 633bd9a25bc029a264910197a4633a200c03e53ed879eb9a1c717e6eaa3f6952；每个原Gitblob/原hunk位置和词法token校验，非GoAST。新postimage逐字匹配实际formatter产物，不运行本机Go/gofmt或重复不变模型。仅格式修订仍须新Linux CI，不能继承ead的新提交接受；真实native Started、sole-close-owner交接、两代cleanup、S2／API／完整恢复与生产尚未完成。

### 2026-10-25 S1 Started持久化与607接线：源码集成，尚待本提交实际Linux验收

S1把真实启动产生的私有Started能力与同store启动前START_ARMED canonical原像绑定，在record入口对已发行能力一次性消费；核原issuer／store／完整owner与fence／时钟／精确重建原像，通过临时私有publication proof及原完整candidate／history／CAS／replace／exact readback记录发生事实。失败或跨库／token／phase拒绝也花费该能力；迟到撤销／过期仅保事实并维持UNKNOWN，不恢复授权或新head。通用DTO不能mint／移除／替换Execution，重开不能重建owner／permit／能力。Execution v1只承载Started，尾部nil omitempty保持旧v3 canonical路径；真实旧金样与新否定用例仍须本提交实际Go验证。Stop前reserve包含新的Started完整尺寸，256历史／2MiB／180秒不放宽。

本切片19源码（8Go+11control）源审dd2ecfe4／独立peer d4705e47；48结构／339字段／98节点，新增5数据类型按53字段与txn尾Execution字段显式深复制，schema源投影bfaed3e6c2938709025876729e2635a27d3e65096ca778687be9a60585ff4012，55指针＋13slice槽及sibling反例扩展，d7非法UTF8 oracle逐字保持。必需607 pin b745efef5b96ad29ececc9f9e4bf465d23277de5c03ff805c8c675abb100da62，旧591／587／585／539／528／407完整集合保留；normal115源／42test／109fmt，compat126／apply134／service141／unknown147，完整诊断70个包test来源。源／YAML／6受影响合成检查不代表Go／反射schema／金样／性能或真实native通过。

有效上下文native Start→Started真实入库实验尚未完成；runtime的sole store close owner交接与双代kernel cleanup另行实现，不把这里的MODEL磁盘或cap当生产磁盘／原生发行。S2 selected-target comparer两个新源仍外部叶子候选，没有collector／私有receipt／时窗／completion；HTTP恢复API、LEGACY/V3 facade、新head、后续普通写、第二恢复及完整系统／生产未完成。

### 2026-10-25 f40的591正常与完整诊断通过：仅关闭本性能／复制底座切片

f40f02bd0a1506b467437cb95aedf39a9f9955e6正常40166486274实际13门success；普通／race各1380语义、591必需全部PASS，format0，原587／585／539／528／407、新4、invalid-utf8明确反例及原schema／dense快路径全过。容量7.51／86.65秒、race包151.443秒，本轮预算内完成。原C.verify实际返回PASS、15199B报告与producer/fresh逐字一致（9448b5ec…fe202a0），Windows原main随后按未改POSIX writer门自然exit1另列，未把它称作完整Linux CLI在Windows通过。独立d1161ccb核12ZIP208成员／1281blob及5分项原checker/fresh、末次源与原件稳定。

诊断40166486286实际5门success；独立a78e5e86核4ZIP42成员／1281blob、113源／41必需test／69全包test／591pin与old587/585、原full strict事件1380／591全部PASS、新4及invalid-UTF8反例、原source/resource/argv/host与producer/fresh逐字一致。full容量85.03秒／pkg149.162秒，single84.22／85.257，120秒定时采样；不相加inclusive堆栈，不据此承诺固定提速或长期稳定。归档见[evidence/sys06-f40-trusted591-acceptance-20261025.json](evidence/sys06-f40-trusted591-acceptance-20261025.json)。

旧fce失败和fresh缺失保留原判。S1 Started持久化仍是外部19文件607源码候选，不能继承f40运行接受；有效上下文native Start→真实Started入库、S2验收／新head、后续普通写与第二恢复／产品API/coordinator及整套系统／生产均未闭环。

### 2026-10-25 fce的591真实断言失败与修订：不改产品门或旧失败判定

fce01f9正常40165751183终态11成功／2失败，普通与race各590必需PASS／1失败，均完整结束而非超时；容量4.48／52.78秒PASS、整包14.331／94.677秒。真实反射schema与dense快路径、原raw草稿边界和sibling隔离新3项通过；唯一新RepresentationFallbackMatchesRaw的invalid-utf8子例失败。诊断40165751185亦4成功／1失败，原full的590／1保留；这些观测不构成整套591或稳定性接受。

root核Go1.23.12官方encoding/json源码：非法UTF8首次Marshal产生转义\\ufffd，Unmarshal得到U+FFFD，后续Marshal合法rune可写literal UTF8；原json.Unmarshal复制本身不保证前后wire拼写一致。新测试错误地把与原decode深相等和重编码等于输入raw绑成同一oracle。修订helper以原decode结果的重编码作expected，仍要求新旧完整DeepEqual／输出bytes相同；另外检查原raw和typed输入未被修改，并在invalid-utf8明确要求原转义raw与原decode重编码不同、两替换rune及两种拼写都实际出现，避免例子未到达却通过。产品typed clone、严格canonical／hash／全部语义／CAS／readback均不改，旧587及新4名单不删。依据：[Go encoder](https://raw.githubusercontent.com/golang/go/go1.23.12/src/encoding/json/encode.go)、[Go decoder](https://raw.githubusercontent.com/golang/go/go1.23.12/src/encoding/json/decode.go)。

同时只转入fce真实gofmt产生的1457B／3个空白hunk，原patch SHA c88fc15724b8fa76204281b737f7f179fdb3a935607064ccc00781e0c3caf4db；transfer收据2c2bc9ec1c563ff42e87225d4d229176ef7b7fc5c6d513407862ebe6a8666e2e。不运行本机formatter，不用旧fce失败原件充当修订后运行；新修订仍待新隔离Linux CI。

### 2026-10-25 591可信深复制候选：完成源审，等待真实Linux验收

本切片仅在verifiedBase与prepared-owned两个已可信入口以闭合typed深复制替代完整JSON解析；base.copyRecord保持原始raw解码，防止共同修改typed store/base后仍通过相等比较的内容进入草稿。实际disk／custody／canonical／外部strict hash／全部candidate与history语义、独立对象／CAS／exact readback均保留。43结构／285字段／90类型节点按字段显式复制，schema pin对未知形状和codec拒绝；sync.OnceValue仅缓存静态Go类型元数据。已知time／UTF8／RawMessage表示差异回到同入口原raw JSON复制，不缓存授权或共享可变业务引用。

新增4个顶层Go声明覆盖dense快路径、nil／empty／sparecap、sibling隔离、表示回退、codec形状及原始草稿边界；必需名单591（bd98cdb360c8eb7fd8c90f0a7a2855a9d8135a3a832f77cfd115ac39c5078857），旧587／585／539／528／407保留。实际normal绑定113源／41测试文件／107格式输入，compat124／apply132／service139／unknown145。原六包、双Go命令、180秒、256历史与2MiB不放宽。来源f20ee3f6与770c344f、独立3Go peer7c877ae9／控制peer736e03e4，6项受影响的合成检查仅是模型证据。当前统一集成源码，不等于编译／gofmt／反射schema／新旧Go及性能已通过；f023失败保留，S1另行适配，完整产品与生产未完成。

### 2026-10-25 f023格式清洁但整套180秒预算耗尽：容量通过不等于整套通过

f023a4448b0503f0c88f151e654a356e4d428382正常40161745031仍11成功／2失败：fmt0、普通1275语义／587必需全PASS；race包180.036秒超时，547必需过／1未完／39未启动。容量115.62秒已PASS（prefix56.529567秒），尾部旧plan测试未完，不能把最后栈位置当其性能根因。其他五类原门成功，原normal fresh缺失与失败保留；独立59ce5dab核11ZIP206成员／1276blob稳定，未进行成功原main观察或临时门豁免。

诊断40161745037为4success／full1failure；容量115.67秒PASS，包180.040秒超时，570必需过／1未完／16未启动，尾部旧ReloadPreparation刚运行时碰到deadline；new2／旧20含子项27全PASS。独立534549cc核4ZIP42成员、原完整120秒采样／资源／source与两模式fresh一致，fullGoAccepted仍false；single117.77秒不覆盖full。原Windows平台限制无adapter保留，未盲重跑或放宽180／256／2MiB。归档见[evidence/sys06-f023-format-clean-suite-budget-failure-20261025.json](evidence/sys06-f023-format-clean-suite-budget-failure-20261025.json)。

下一优化仅外部开发中：盘点可信已验证record的三次完整JSON typed decode能否改为全字段深度脱离复制，并保每次实际disk／canonical一致性、外部strict decode／hash、全部candidate／history语义、独立base／prepared、publish一致性及CAS读回。浅复制／共享引用／缓存权限不接受；新字段漏拷必须fail closed。尚无该新源码集成或性能接受，S1仍仅独立候选，完整系统／生产未完成。

### 2026-10-25 850实际587全部Go及full诊断通过，正常格式失败仍保留

850fbac8cee1422e18bff9c927b94fc5e78fb8e8正常40161229161仍11成功／2失败：普通／race各1275语义／587必需完整PASS，旧585／539／528／407、authority27／Start19和新2负例均通过，容量6.32／74.50秒、race包119.637秒。实际gofmt产生457字节patch，仅新sealer注释前缺一空行，不能因此宣称原完整verify／fresh通过；原失败及fresh缺失保留。独立ac0192c7保11ZIP206成员和全部其他五类原门。

独立诊断40161229105实际5／5成功，原完整full事件门1275／587全部通过、新2及旧20／27全PASS；full容量106.12秒、包169.763秒，single115.99秒不与其他轮混算。独立3ba4847f核4ZIP42成员、1274源blob、112源／587pin及old585子集、原函数重算和两模式producer／fresh一致，真实120秒画像与sandbox／资源边界保持；诊断formatter只查tag文件，不能覆盖正常106文件格式门。结果证明本轮预算内完成，不保证因果提速比例、未来稳定性或生产可用。

格式transfer cef17a9c由实际850Gitblob／单hunk及原457Bpatch严格派生：v3.go cfddf785…17ce4b→7c6a36e5…7202e6仅加一LF，未本机Go／gofmt或重复无变化模型。新格式源码须新CI，不能继承850运行接受。归档见[evidence/sys06-850fbac-go587-pass-format-failure-20261025.json](evidence/sys06-850fbac-go587-pass-format-failure-20261025.json)。S1仍仅独立候选，完整恢复及系统／生产未完成。

### 2026-10-25 同次context／候选根hash去重与587接线：源码待新运行

本次在beginRecovery保留同次实际SourceV2严格context和一份detached descriptor，减少重复legacy编码／解码和循环descriptor复制；候选prepare改由专用sealer自行一次计算根hash，再执行与外部strict validator逐字共享的全部Contents语义及每个history验证、bounded canonical marshal。外部decode／encode／原根hash门保留；typed base／draft／prepared独立解码、实际CAS／replace／exact readback／publish一致性校验不削弱，不缓存批准或能力。成功begin／revoke的直接完整V3序列化静态计数由5到4，不是整体CPU下降比例或实测性能承诺。

增加两个有意义负例：新候选必须通过完整外部严格解码且错误根摘要仍拒绝；分别变异每个独立归档plan的原source revision、重算内层PlanSHA和外层根摘要后仍须拒绝，避免靠摘要不一致掩盖source校验缺口。新必需587（pin14e88fa4…5d2951），旧585／539／528／407集合及旧79方法体逐字保留；112绑定源、40测试文件、106格式输入、原六包／两Go命令、256历史／2MiB／180秒均保持。来源A最终integrated-587-v2 source-only收据a58668cf，原3源及初6源冻结对象不覆盖；新的Go编译、格式、普通／race／诊断及性能结果尚未取得。Started事实S1仍在独立树，未混入本次。

### 2026-10-25 04bf原诊断20项恢复，正常／full均仍容量超时

04bf4ef751bc95f1b288c49d5eca3d96917f9f2f正常40159807452为11成功／2失败：普通1273语义／585必需全过、容量11.04秒、格式0；race180.046秒超时，489必需过／1未完／95未启动，容量观察约123.159秒仍无终态。其他五类原门通过不覆盖该失败，foundation fresh工件实际缺失，不推断其成功。独立d11968a3保11ZIP206成员、1272源blob及下载失败历史；只补未完成下载，没有重启Go或产品门。

诊断40159807441为4成功／full1失败。旧ca原20必需及含子项27失败在新原Go JSON全部PASS，支持两harness接缝已恢复；full仍489过／1未完／95未启动、包180.047秒超时、容量仍run，不能标完整Go接受。full采样120秒完整、producer／fresh一致，独立bc105b49保4ZIP42成员和原函数重算；legacy单case111.07秒PASS不覆盖full失败。原CPU文本窗口120.18秒／117.71CPU秒，cum涉及prepare／begin／Marshal／strict decode，instrumentation占大；不相加重叠统计、不宣称单栈或某个serializer是唯一原因。下一性能修复仅减少同次操作重复工作，外部strict hash／完整candidate及history语义、原79体／256／2MiB／180保持；尚未有新性能接受。归档见[evidence/sys06-04bf-harness-recovery-capacity-timeout-20261025.json](evidence/sys06-04bf-harness-recovery-capacity-timeout-20261025.json)。S1仍在独立树源码开发，完整恢复／产品／生产未完成。

### 2026-10-25 ca正常585全门接受，完整诊断自身环境不兼容保留失败

ca5431e362e3a8dfe1c54f9458cb66e5510cebfd正常40158396898实际13／13成功；普通／race各1273语义与585必需全过，旧539／528／407及新authority27／Start19齐全、格式0，原256容量6.62／79.12秒，race包124.382秒。foundation4cdd8b77与五门60aa20b4独立原件复核通过，原完整verify返回15055字节与producer／fresh相等；正常12ZIP208成员及1270Gitblob稳定。原Windows main在POSIX报告写入门自然exit1保留，不把本机原CLI称成功。

诊断40158396908实际4success／full1failure，不能被正常成功抵消。full采样120.210秒完整，但565必需过／20失败、无timeout，容量93.74秒PASS；独立518a1942保4ZIP42成员及两模式producer／fresh一致。原Go输出与源码支持两个新harness原因：umask077改变故意0644权限反例，profile-tag TestMain拦原MODEL／flock helper子进程；未逐个重现每个失败，不把20失败直接称产品回归。pprof仅mihomodeploy窗口，前后资源不是逐测试或有效祖先CPU证明；未独立重算pprof数值，无Path／AST适配。归档见[evidence/sys06-ca5431e-normal-acceptance-profile-failure-20261025.json](evidence/sys06-ca5431e-normal-acceptance-profile-failure-20261025.json)。诊断修复须保所有原测试体、585、256与180秒并重新真实CI；完整恢复API／coordinator／新head／后续发布／再次恢复、整套产品及生产仍未完成。

本次修正仅两个诊断源，真实新运行待验：父Python保umask077／私件0600，只对FULL的GO_TEST使用[Popen的POSIX子进程umask参数](https://docs.python.org/3.12/library/subprocess.html#subprocess.Popen)设0022；不改变产品权限校验。TestMain支持原有两条精确MODEL／probe子进程协议，以full-only私有parent marker、实际PPid及父／子exe身份核对约束，子进程只运行原helper，不打开或写父profile；clean-env MODEL无需继承profile凭据，probe检查继承绑定。默认single行为、公件18／20与报告schema不变。源码／有限模型不能代替新Linux编译、格式及真实原失败用例通过。

### 2026-10-25 完整六包race诊断接线：源码复核通过，真实运行待验

诊断现增加固定FULL_CONTRACTS模式：以原六包race命令为基础，仅增加固定诊断tag与`^Test`过滤；完整Git manifest绑定的六包68份测试源须无Example／Fuzz入口，否则拒绝。正常13任务、585必需声明、原180秒超时、完整256历史和所有产品验证字节保持。默认单case的旧三任务／18公件／60秒机制保留；新增full／full-fresh两任务／20公件／120秒采样。CPU画像仅属于mihomodeploy进程的有界窗口；前后CPU／affinity／proc／cgroup观测围住六包Go CLI及编译，不冒充逐测试资源或因果归因。

真实旧585完整Go JSON与2de超时原件已分别通过新reader及原严格事件门对照：后者仍489通过／1未完／95未启动，原Go失败不会被captureVerified或fresh成功转绿。独立peer收据83a0c976…71a5db核21负例及5来源guard检查；仅为源码与有限CPU数据审阅，新full Go编译／格式、120秒采样、实际资源、producer／fresh与独立原件复核尚未执行，不能称根因或性能修复。本轮仍无生产、main、Registry或原生恢复闭环变更。

### 2026-10-25 2de实际格式清洁，完整race再次容量超时：不覆盖失败

实际2de5661481603d75f3483b599614f89747295a9c／40155992395终态11成功／2失败，格式patch为0。普通1273语义／585必需全过，容量10.99秒；race仅489必需通过、1未完成、95未启动，包180.047秒超时。新增authority27／Start19及owner-expiry／maxRevision子例均通过，不能代替未完成的完整race。原79旧方法体、256容量／180秒保持，1268实际Gitblob和112源／13ZIP成员稳定。五类其他原门独立成功，整体失败仍保留在[evidence/sys06-next7-2de-race-failure-20261025.json](evidence/sys06-next7-2de-race-failure-20261025.json)。

原Go事件显示容量在包开始57.294115秒后启动，到包失败时已观察122.753361秒，没有终态；不能将包180秒冒充容量独占180秒。新panic位于prepare→recordHash／json.Marshal，只是一瞬间采样，未证明主要CPU成本或外部资源原因。与上一轮2b8两套585完整通过／容量77.69秒并存，不能以仅格式变化推断本次通过、保证稳定提速或只重试刷绿。当前扩展独立诊断为固定完整六包race模式：原单case60秒机制保持，完整模式拟采样120秒以覆盖前缀和容量中段，仍Go180秒、完整256和正常13门不动。源码正在实现，尚无此新实际采样；native恢复／API／coordinator／新head及完整E2E未完成，生产未动。

### 2026-10-25 2b8实际Go与585完整通过：新组件仍非原生恢复闭环

开发提交2b8ccb68e5ca3297667b5291ae7519de678812bb的实际基础40155559362为11成功／2失败；失败阻断是158094字节非空格式patch。真实Go编译、普通／race各1273语义及585必需完整通过，旧539／528／407、授权27与Start19齐全；短租约过期子例普通0.02秒／race0.28秒通过，256容量6.32／77.69秒，race包122.560秒，原180秒门保持。独立基础ede23d0b…c19bc核1267Gitblob／112绑定源／13ZIP成员。实际GoExit均0、stderr空，不以format工具exit0冒充格式清洁。

五类其他原门和fresh原报告独立复核通过，四门c4b3df17…7b1e93、UNKNOWN30fef52c…af88db、归并067b6197…9dca9a保10ZIP／193成员与终态11／2失败；138服务源／144UNKNOWN源的输出manifest按输出JSON核验。原进行中快照保留、终态追加，不重跑已成功门。七源格式现严格由原2b8 Gitblob／CI hunk转入，未本机Go／gofmt，不新增语义修改或重跑未变CPU模型，须下一新CI证明格式与全门同时过。Start19的有效范围是结构／一次能力与拒绝模型，未证明有效context下的真实恢复Start、API／coordinator、新head或完整恢复E2E，生产未动。

### 2026-10-25 恢复授权／一次启动组件纳入585接线：尚未实际编译

现将此前独立source-only的授权2源、一次启动5源纳入开发检查器和Linux验收源清单。必需声明由539增加46至585（授权27、启动通用10、Linux9），保539／528／407 checkpoint，foundation源112、测试文件40、formatter106，compat／apply／service／UNKNOWN绑定源123／131／138／144；原6包、13任务、256容量及180秒测试命令保持。接线和声明数不等于已编译或已启动进程。

授权组件使用借用的当前SnapshotManager、完整范围／角色／独立主体复核及当前WAL绑定，STOP与START分别检查实际阶段、审批和一次permit；关闭只清自己的registry，不冒充拥有共享manager。启动入口只消费实际store发行permit一次，读私有ArtifactStore和ELF／命名空间／端口，准备后再核当前WAL、owner／fence／nonce／租约／CAS／撤销与完整初始绑定，最后只调用一次原Start；失败／超时持有实际owned句柄交由上层收尾，不自动Stop／重试／PUT。fresh凭据检查与OS调用间的原子串行、完整coordinator尚未接齐，不称原子撤销或自动恢复已完成。

预审发现新Start短租约MODEL夹具曾协调改写已开store.raw／record，现快照校验会提前拦截并遮蔽目标lease-expiry分支。仅在该新测试中改为fresh严格open后实际acquire短lease、逐真实结构transition写入／读回，保留完整seal校验；旧79恢复方法体、539声明与产品Go验证不变。MODEL没有真实Stop／Start或凭据授权，issuer永久64条claim上限是显式failclosed预算，不是免维护生产能力。真正原生启动、record-only事实、collector／新head、closed journal、后续普通发布、再次恢复和API／完整E2E仍待后续实现与验收。

### 2026-10-25 40c6本阶段隔离验收完成：仍未上线或完成恢复闭环

接受的运行源码为40c6b4e2f1f65f9d16aeec8e3a6538277d63d62a。基础40153931108实际13／13成功，诊断40153931092实际3／3成功；普通／race各1213语义、539必需、旧528／407与新11全部通过，原容量256分别6.59／79.92秒，格式差异为空。原完整foundation verify真实返回报告与CI producer／fresh的14147字节完全相同；本机原main随后因POSIX报告写入限制自然退出1，观察未改函数、平台或退出码，不称Windows运行了Linux CLI。

compat／apply／service／candidate／UNKNOWN五类原完整门独立复算通过，producer／fresh原报告逐字一致；service与UNKNOWN的CPU／CLI sourceGitVerified范围差异仅在比较副本处理，原报告保留。实际1258个Gitblob及各ZIP摘要／CRC／成员／原件前后稳定已核。完整正常门12ZIP／208成员与独立诊断2ZIP／20成员分别留存；这些是有界实验公开证据，不独立证明完整私有WAL、私有配置来源、任意payload、互联网业务或服务端实际接收次数，controllerReceivedCount保持null。

规范字节快照优化的本阶段性能阻断已通过完整原门解决；不保证稳定提速比例或任意负载性能。诊断三次单case174.51／93.87／122.54秒来自不同运行，profile只覆盖前约60秒，仍有本地符号化可能不完整警告，未独立重算pprof数值。下一7源及585声明接线仍只是外部准备，尚未纳入本阶段。完整恢复API／closed journal facade／collector／新head／后续普通发布／再次恢复及真实恢复E2E仍缺，整套产品、灰度与生产未完成。本次后续归档仅文档，不替代40c6运行源码证据。

### 2026-10-25 0aed153实际运行：普通／race全部539通过，格式修正待下一CI

基础40153568233的原普通和race事件门均完整接受：各1213语义测试、539必需，旧528／407、新11及maxRevision子例全部通过，零未完成／未启动。原256历史容量普通6.50秒、race77.48秒，mihomodeploy包分别15.100秒／108.593秒，原180秒门保持。完整CI仍11成功／2失败，唯一实际阻断为4031字节非空gofmt.patch；工具formatExit0不代表格式清洁。独立收据mihomo-0aed153-foundation-audit-20261025-agent/result.json（b4397bbf…eaf2124）核1257Gitblob、105绑定源和13ZIP成员。已按原0aed Gitblob／hunk严格转入唯一store.go格式，不本机Go／gofmt，仍须新CI确认。

独立诊断40153568228实际3任务全成功；原单race容量case93.87秒、格式空、profile完整约60.21秒／65254字节，producer／fresh字节一致，独立收据3006d7d0…4c5b7c1。与此前174.51秒比较仅为两次观测，不是稳定性能承诺；符号化可能不完整警告和pprof数值未独立重算边界保留。诊断单case的93.87秒与完整基础门内77.48秒属于不同运行，不能混成同一测量。新11在基础两套实际通过不等于下一授权／Start7源已编译、完整恢复E2E或生产完成。

### 2026-10-25 已验证规范字节快照优化：源码冻结，真实验收待执行

本次store／test两源已冻结：仅复用同一store中已通过完整外部canonical／全部历史校验的精确规范字节；私有快照只在open成功或完整新候选实际提交并精确读回后发行，不是停止／启动／批准授权。快照绑定原store、发行身份、不可变字节、完整摘要和世代，缺失或不匹配直接拒绝并封锁，不从篡改字节重新生成证明。每次仍实际校验磁盘custody并读取，逐字节比较磁盘／store.raw／快照，完整Marshal当前嵌套record以检查内存一致性；产生的base与draft分别解码、无可变别名。

准备前及写前继续比较完整base记录，候选仍全量semantic／全部历史校验。预提交实际CAS、真实replace、写后精确读回及custody不减；UNKNOWN／失败读回／关闭／时钟回退清除快照，明确未提交只保留原快照不采用候选。重新打开始终完整解析外部字节，内存世代不冒充重启后的防回放或授权。此次有意识替换此前“没有跨操作验证复用”的实现，复用只针对同store已证明相同的规范字节，不复用业务权限或跨store证明。

新增11项快照反例声明，a727原68个恢复相关测试方法体及旧528全部保留，必需名单为539并保旧528／407独立checkpoint。原256历史容量方法、常量、两条180秒普通／race命令完整保留；诊断标签文件仅转入实际CI格式补丁。本机未执行Go／gofmt，独立源码peer及CPU模型另存收据，尚未证明新11项运行或性能改善。下一授权／Start7源仍未纳CI，完整恢复／新head／后续发布／真实E2E及生产仍未完成。

### 2026-10-25 a727实际诊断：单独race容量通过，完整基础race仍失败

实际诊断40151267013为2成功／1失败，但原Go退出0，唯一原容量case通过174.51秒、包175.543秒。失败的明确因素是诊断标签文件7791字节非空gofmt.patch；基础工作流的格式差异为0，不能混为产品格式失败。已严格按a727原blob逐hunk转入该诊断文件，未本机执行Go或gofmt，仍待下一CI确认。

原CPU profile完整写出71169字节，定时停止约60.20秒；仅覆盖用例前段，不能代表后约114秒。实际top前三race插桩flat共53.18%，cum verifiedBase15.02%、decodeV3约14.90%、JSON Marshal11.57%，这些累计成本重叠，不能相加；regexp只有0.93%，不支持此前仅凭栈认定正则主因。pprof保留本地testbinary已被Go清理造成符号化可能不完整的警告。fresh只核二进制结构／源绑定／事件，不独立重算pprof数字。1255个实际Gitblob及20工件成员已独立核，producer/fresh原报告逐字一致；本机原CLI因Windows平台实际拒绝，另有明确标注的PurePosixPath适配CPU审计，不冒充原Linux CLI通过。

同提交基础40151266990为11成功／2失败：普通1201语义、528必需及旧407全部通过，容量16.90秒；race必需432通过、1未完、95未启动，包180.041秒超时且容量没有终态。局部诊断case通过不能覆盖完整race失败。详见[evidence/sys06-capacity-profile-actual-a727-20261025.json](evidence/sys06-capacity-profile-actual-a727-20261025.json)。下一优化将针对同store已完整验证规范字节的重复解析，同时保持外部／重开严格校验、每次真实磁盘读回／CAS、全候选及全部256历史校验和180秒门；尚未证明性能修复。完整恢复／真实E2E及整套产品未完成，生产未动。

### 2026-10-25 独立CPU诊断源码已冻结，尚未实际采样

新增5个诊断专用文件，未改既有13任务工作流、528必需名单、原容量测试正文、实际256常量或180秒门限。独立3任务工作流仅允许开发分支：Go1.23.12在私有net／mount／PID空间、UID10001、零能力、清环境及只读源码／GoRoot运行唯一原容量case。仅显式诊断标签启用TestMain；60秒定时器自身停止CPU采样、跟踪writer错误并Sync／Close保存原profile，不依赖180秒panic后的defer。外层600秒包含编译与本地工具，未替代或延长测试自己的180秒。

原profile以有界base64 JSON、Go原事件、工具stdout／stderr、实际命令／PID／exit、全Git源码绑定和主机前后观测保管。PPROF只本地符号化，不开HTTP；完整原件校验与原case成功分字段，测试失败仍保持CI失败。fresh仅独立重读profile gzip／protobuf结构、源码与事件，不重新计算top／cum数值，pprofNumericRecomputeProven保持false。静态源码复核通过不代表已编译／采样；实际profile、格式、编译及case结果待新的Linux CI。下一授权／Start7源未纳本次，完整恢复和生产均未完成。

### 2026-10-25 28e6e48实际验收：普通528通过，race仍超时，准备独立性能诊断

真实Linux运行40148979938终态11成功／2失败。普通1201语义及528必需声明均通过，原256历史容量用例17.37秒PASS；race的10新反例全部通过，但必需432通过、1未完成、95未启动，容量用例仍触发包180.047秒超时，未观察断言失败／跳过／DATA RACE警告不等于race通过。实际25095字节格式差异已严格按本提交preimage转入2源，未本机执行gofmt。

五类分项原门及fresh已独立离线复核通过；原基础失败没有被覆盖，见[evidence/sys06-recovery-28e6e48-failure-20261025.json](evidence/sys06-recovery-28e6e48-failure-20261025.json)。本轮超时采样位于verifiedBase的完整历史／descriptor正则校验，不能据一次stack断言主要CPU成本。下一步准备使用Go1.23.12标准runtime/pprof在独立隔离CI诊断，原256方法、180秒门限和完整普通／race门保持。当前未执行profiling，也没有新恢复可用或生产上线结论。

### 2026-10-25 锁内事务校验优化：源码冻结，待新Linux验收

本次实际修改3源：恢复store、其测试和恢复transition。每次锁内操作从实际磁盘完整canonical／语义解码签发private一次base，复制时仅对已验证原字节作独立typed解码；完整新候选校验后形成独立prepared字节和记录。提交前仍重新核实际custody／磁盘原字节CAS，写后仍实际精确读回及custody验证，才采用private独立记录。不存在store跨操作验证缓存；临时发行身份在所有退出、关闭、时钟封锁时清理，已知失败消费不可通过恢复字节复活。generic raw publisher仍单独严格验证实际旧v2和显式演进，不借造v3 base。

原58恢复／计划测试方法、256历史填充及180秒限制保持，新增10项事务反例声明。总528必需声明保留旧518及原407；尚未Go编译／执行或性能验收，不称race已修。实际CI的3份格式差异另按原件转入，新授权／Start组件仍不纳本轮源清单，完整恢复和生产状态不变。

### 2026-10-25 a14f746实际验收：普通完整通过，race容量仍超时

真实Linux运行40147159085终态11成功／2失败。普通套件1191语义／688顶层全通过，518必需及原407全部齐全；原256历史容量用例39.22秒PASS、包50.048秒。race在同容量用例触发包180.05秒超时：422必需通过、1未完成、95未启动，原407仅328通过、79未启动；没有断言失败或DATA RACE警告不能当作race通过。实际12974字节格式补丁已逐hunk转入3源，仍须下一CI确认。

独立基础诊断、apply／service／compat／candidate四分项原门及UNKNOWN原门复算已保存，producer／fresh分项逐字一致，但这些成功不能覆盖基础race与格式失败。详见[evidence/sys06-recovery-a14f746-failure-20261025.json](evidence/sys06-recovery-a14f746-failure-20261025.json)。新race采样栈位于同事务反复decode／validate／recordHash路径，尚非性能剖析；下一修复针对锁内已验证base及完整校验prepared候选的重复工作，必须保真实磁盘CAS／完整新候选校验／写后精确读回、256容量及180秒门限。

### 2026-10-25 恢复底座实际失败后的修正：尚待新Linux验收

开发提交9fb1ccaf的真实CI40145206729终态11成功／2失败，整体未通过。基础普通／race均在256次恢复历史容量用例触发180秒超时，另有278636字节实际格式差异。原件和失败诊断保留；原514项必需顶层声明中每套仅420项通过、1项开始后中断、93项未开始，不能借其他分项通过推导完整回归通过。

本次修正按实际CI原始preimage转入12源格式差异；性能实现每次完整v3校验从实际canonical SourceV2完整解码一次，局部context只复用不可变原记录与按完整descriptor JSON字节匹配的目标工件校验，逐条恢复计划的绑定、时间、预算和有序摘要继续检查。public计划构造仍完整验证输入。旧54个恢复／计划测试正文、256次容量填充及180秒门限保持，新增4项反例声明，总必需名单518并保留旧514与原407；声明增加不代表已执行或性能已修好。

下一阶段真实凭据恢复授权和原生新Start源码不在本次修正源清单内，不借用本次CI。完整API、closed LEGACY/V3 facade、collector、新head、后续普通发布和真实恢复E2E仍待完成；当前修正没有生产部署、main合并或Registry发布。

### 2026-10-25 739314 真实实验与原始失败：修正待新 CI

58 文件开发提交 73931438ecd47d9c6baa22cf5878b91a55f78242 已推送并远端读回一致。真实运行 40136303169 的 11 任务终态为 7 success／4 failure，整个运行失败。新增 service 的实际 Go 进程退出 0，producer PASS，58 份公件完整，包括 4 阶段 32 份逐 GET 原文、11 次实际产品 HTTPS 调用、持久 head 和实际清理。Reload／Do 累计观测是 0→1→1，五端口均实际 ECONNREFUSED。该实验没有通用互联网流量、生产目标或完整企业能力证明。

原 service 检查器因 37,361 字节非空格式差异真实拒绝，service/fresh 没有通过。独立复核从 102 份原提交 Git blob 取源，校验 ZIP API SHA、成员 CRC 和所有原件摘要；仅在独立 AST 副本跳过该 gofmt.patch 的空字节条件，其余 stderr、退出、32 正文投影、HTTP、head、计数和清理原语句全部到达原 PASS 返回之前的检查点，未执行原 PASS 返回。这是限定诊断，不是原检查器、正式 Linux CLI 或完整 CI 通过。原件和诊断分别在 D:/CodexData/workspace/mihomo-ci-observed-739314-20261025 和 D:/CodexData/workspace/mihomo-service-739314-independent-20261025-c。

基础普通／race 均退出 1，各 864 个语义 pass、8 个顶层和 4 个子例 fail、零 skip，另有 496,232 字节实际格式差异。31 文件已严格按该 CI 的原提交 preimage／hunk 转入；服务的 4 份格式差异与之逐字节相同，本机未跑 gofmt。修正限定三份测试文件：新建并核验 0700 私有专用 leaf，避免正负夹具被无关权限条件提前拦下；提交后读回故障仅在下一次真实模型替换之后注入，并核写次数及原 ACK 保留；三种非法消费情形改为顺序子测试，确保固定端口 child 的原 Cleanup 在下一情形前完成。产品权限、目录、一次消费和不确定性安全门未放宽，顶层 407 项名单不变。新修正尚需另行统一提交及实际 Linux 普通／race、service 和 fresh 复验；保留本次所有原始失败。

### 2026-10-25 owned 服务源码与真实 HTTP 验收接线：尚未运行

新源码组合以实际独占创建、私有 marker、当前身份与完整资源范围、实际拥有的内核进程及读回为初始化前提。HTTP 支持发现两份实际准入候选、创建计划、读取 head 找回操作、不同主体批准、执行、撤销和查询；默认关闭写入，不接受调用方提供 PID、控制地址、凭据或自称的运行证明。已有 v1 状态保持原编解码，不自动迁移；拒绝错误版本或 marker 时必须在恢复写入前检查。新 v2 保留成功和非成功终态的完整历史，不靠删记录腾出容量。

真实服务验收源码使用正常 RunWith、TCP、TLS、当前身份文件和实际 service；在实际 create handler 返回后主动断开连接，区分服务生成的 201 与客户端未收到的响应，再通过 head 找回持久操作。这是显式传输故障注入，不是自然 WAN 丢包。独立批准后的执行要求实际适配器 204、受支持的新投影、局部数据面路由和 typed head 推进。WriteClient 的实际 Reload 入口与 Do 调用点累计计数分别采样；执行增加一次、重放不增加，不能用 WAL 不变代替请求次数。Do 次数仍不证明服务端收到，controllerReceivedCount 继续为 null。

新固定 service_contract.json 与 service_worker.py 定义 58 份成功公开原件：4 阶段各 8 份原正文、transcript 和 verification（40 份），语法 3 份、HTTP 报告、服务 journal、内核 stdout/stderr（7 份），worker 7 份和原有宿主／消费事实 4 份。verification 保存实际参与摘要的 canonical 原字节，不额外 GET，不重序列化补造原件。单正文私有暂存上限 256KiB、每阶段含 receipt 共 2MiB、私有总量 64MiB；这是有界双候选实验，不是通用企业配置容量上限或 RSS 保证。

worker 持密围栏覆盖实际控制器与路由标记、两份原 YAML、HTTP 临时凭据和实际 TLS 叶私钥；HTTP []byte 的 Base64 内层和选定头均须解码后检查。围栏失败默认不发布原始输出，不用脱敏替换字节。首次 12 项与扩展后的 14 项 Python 合成围栏模型分别实际通过，原始记录在 D:/CodexData/workspace/mihomo-service-disclosure-models-mmw1t_vk 和 D:/CodexData/workspace/mihomo-service-disclosure-models-irzpt3nh；后者保留 PID、退出、原输出与 6 份源摘要。只导入安全 helper，未执行 worker/main、Go、内核、namespace 或产品服务；不声称任意隐写／编码均被覆盖。

工作流已增加 service 与 service-fresh 源码接线，YAML、26 段 shell 语法、14 段内嵌 Python 及 11 job 依赖图实际核过，原 9 job 的非执行配置保持。独立检查器、清理原始元数据和最终源名单已形成；独立服务证据的 38 项合成模型首次通过，最终组合的既有 139 项也通过，连同围栏 14 项共 191 项 Python 合成检查，均不是 Go／内核／HTTP 实测。静态门保留原 306 项并新增 101 项，共 407 项必执行 Go 顶层声明；服务独立检查器绑定 102 份具名源和 58 份成功公件，这不是完整编译依赖的外部证明。尚未取得新提交的真实 Linux Go、产品 HTTPS 或 fresh 运行结果。独立公开复算也不证明私有 YAML 来源、完整私有 WAL、任意 payload、互联网业务或生产。UNKNOWN 即使读到候选状态仍阻塞；另需独立预批准的停止旧 owned 进程、实际 Wait／监听排空及新 epoch 启动恢复，当前尚未完成。整套产品的 DNS、其他内核、企业协议／业务、UI、容量、浸泡、灰度、生产读回和运营交接仍未闭环。

以下条目保留当时记录，以本节最新核对为先。父提交 bfb834b 的真实运行 40126982016 已取得：普通／race 各 400 项语义及 306 项强制声明通过、实际 apply 通过，36 公件内的 16 份正文独立重算匹配；整门仍因实际格式差异失败。四份格式源已按原 CI patch 转入，本机没有运行 gofmt；不能把该父代实验替代新服务验收。

### 2026-10-25 逐次GET原件与独立投影：源码及合成检查完成，真实新版待验

上一修复提交4815ecfa1b9b7bf607e8862cfd9f9b3f4e28c1bc的真实CI 40123345295已读到终态success，9个任务全部成功，包含contracts、compat、apply及各自fresh。8份ZIP已按API摘要、CRC和成员摘要保管在D:/CodexData/workspace/mihomo-ci-observed-4815-20261025。独立原件复核D:/CodexData/workspace/mihomo-4815-independent-audit-20261025-a/run-20261024T194627176022Z/result.json确认普通／race各378项语义通过（291顶层＋87子项），原284项强制用例逐名run／pass、零跳过，先前失败身份用例两套均通过；foundation／compat／apply／candidate共4对生产者与fresh报告逐字节相同。65个ZIP成员、8ZIP、8custody及2元数据索引共83份文件前后摘要稳定，83不是ZIP成员数。本机只读解析与字节核对不冒充正式Linux CLI重跑。该结果属于旧v1实验，不证明下述新v2采集代码通过，也不证明产品API、批准、head推进或生产上线。

当前开发候选保持旧ReadStable接口和原28项读回测试完整字节，新增ReadStableCaptured与22项Go采集测试声明。采集沿用同一次HTTP响应和同一解码正文，不额外请求；每阶段两轮4端点，共旧新16份正文与2份逐槽记录。失败时保留实际私有前缀及错误，不补造未读取正文。证据句柄为私有共享引用，复制Getter结果，Release使别名共同失效并释放单次占用；不声称安全擦除、硬实时或进程RSS上限。

单次采集整体时限取调用方、配置和5秒的最小值；选定头16KiB，正文接受8MiB及单一超限探针，归档容量8×(8MiB+1)，元数据1MiB。CompletedBodies仅统计真实自然EOF、读取无错且长度未超限的物理正文，之后关闭或JSON深度失败不抹掉已观察事实；COMPLETE还要求关闭、头、形状与所有资源门通过。旧新阶段分别导出、释放，失败原件仅私有保留。

独立Python模块从实际公开逐槽记录与正文重新验证长度、摘要、顺序、EOF、关闭、头及形状，重建两轮受支持General／代理／规则投影与UUID见证，不依赖生产者摘要作为输入事实。Go1.23的字段顺序、映射排序、UTF8／HTML转义、null与数组区别单列实现，实际运行要求Unicode15.0.0；源码与向量有固定官方依据，跨语言实际一致性仍须新版Linux CI证明。

apply合同、报告和独立报告升级v2，成功公件由18增至36，绑定源由61增至65。生产者只可在16正文实际落盘后把perGetRawEvidenceAvailable置真，不能宣称Python已经复算；独立检查器只有重建通过后才置independentProjectionRecomputeProven为真。expectedSourceIndependentlyProven和privateDisclosureFenceIndependentlyProven始终为false：公开原件不独立证明私有YAML来源，也不重复持密围栏。服务端接收次数仍null，完整payload、批准、API、head、互联网业务及生产旗标仍false。worker同时检查原件与解码后头值的私密围栏，失败默认不发布新18件，不能用脱敏替换字节。

主集成者首次实际运行25项基础证据、34项兼容、47项应用和33项独立投影合成模型，共139项，全部退出0且零跳过；D:/CodexData/workspace/mihomo-captured-models-vwhqgf8t/result.json保留实际PID、原stdout／stderr、退出与源码前后摘要。交叉复核随后指出应用模型缺少直接破坏新正文的接线反例，已在原同名模型内增加仅修改baseline-get-01.body、保留报告及记录不变的拒绝检查；只重跑受影响47项，实际全通过，D:/CodexData/workspace/mihomo-captured-models-qo0eybx5/result.json保留新执行，另25／34／33源码未变，不重复运行或增加测试数量。它们是Python合成检查，不是Go、内核或生产验收。基础门保留旧284项声明并新增22项，共306项；本机未运行Go、gofmt、worker、内核、namespace或产品服务。新候选尚未提交／取得真实36公件，SYS-06仍未完成。

### 2026-10-25 实际应用场景已运行，整体验收仍失败

已读取6231584的实际运行40118290564及9cc8162的40121289102，两次整体均failure，兼容性与对应fresh均success。基础ordinary／race各377项语义通过、290项顶层通过、1项顶层失败、零跳过；唯一失败为TestLabKernelInitialUnobservedIdentityNeverCreatesCapability。初始化身份没有建立时，旧identity仍用零bound.PID调用observer，覆盖了测试保留的实际已启动PID；修正应在任何新观察／验证I/O前要求完整源绑定的初始身份，保留原Start、错误持有者、stop／Wait及进程消失断言，不能仅修改模型Store来掩盖问题。

9cc真实apply标签用例已通过（实际Go事件1.52秒），报告记录旧／新各8次GET投影、缺失／错误令牌401、一次客户端Reload调用及204、两个本地真实代理链路的A→B字节／计数对证、受控身份及退出清理。它不包含产品API、独立批准、head推进、互联网业务或完整未知恢复；九范围旗标仍为false，controllerReceivedCount仍为null。其成功不使整条CI通过。

应用原件实际有71,427字节非空gofmt.patch，原独立checker及fresh正确拒绝；基础格式差异另为434,926字节。实际格式补丁已分别按原件转入20份旧源和1份应用测试源，没有本机运行gofmt；随后仅两份Linux内核身份源／测试作定点修正，仍须新Linux普通／race及全9任务确认。原CI／格式失败不覆盖、不改判。

实际应用原件经独立离线复算，原函数49条非格式语义语句及交叉约束通过，格式门仍保持失败；49是原源码语句，不是49个测试。D:/CodexData/workspace/mihomo-9cc-apply-semantic-subgates-20261025-b/result.json保留18公件、19 ZIP成员、61个Git blob的字节绑定与前后稳定证据。Windows原严格custody读绑定拒绝单独保留，辅助字节／Git绑定不能冒称正式Linux CLI通过，也未放宽产品读守门。逐GET原文独立重算仍未实现。

下文保留历史阶段，发生冲突时以上述实际结果及后续新CI为准；当前还没有整套产品上线或生产切换结论。

### 2026-10-25 新增真实应用实验入口：源码与证据检查阶段

开发分支增加带`linux && chengwang_mihomo_apply`标签的唯一真实内核实验、独立worker／入口／合同、公开原件检查器及其合成反例模型；CI增加apply及apply-fresh，不替代旧7个任务。新Go标签用例与合成模型分别记录，源码存在不代表已经执行。6231584此前提交的284项基础声明保持不变。

实验按固定官方候选来源，拟在无默认外网出口的私有net／mount／PID空间，以UID10001、零能力、只读源码与ELF运行：实际旧完整输入启动、受控进程与监听归属、合法／缺失／错误令牌探测、两轮各4个GET的旧投影、实际本地A代理链路、候选完整正文语法检查、一次客户端Reload调用、两轮候选投影、实际B代理链路及确认退出／清理。客户端只能拨实际mixed端口；代理fixture仅接受固定CONNECT目标并实际访问独立本地origin，三方完整读取摘要和路径计数交叉核对，不伪造Mihomo响应。

18份成功公件只包含安全观测／真实原始流；三份私密正文／密钥材料不导出。无法通过私密围栏时抑制原流并单列worker-failure.json，不能用脱敏摘要混充stderr或补造空原件。heavy child的启动意图、实际PID／pidfd及Wait观测保留root私有耐久journal；不按裸PID／PGID扩大终止范围。fresh任务只重算原件与源码，不第二次执行内核。

公开检查器无法独立重算未公开的逐GET正文，也不能独立重做持私密材料的围栏；报告明确依赖source-bound worker，相关证明字段为false。一次客户端调用不是服务端接收次数，controllerReceivedCount保持null；本地origin成功不是ChatGPT等互联网业务通过。当前实验没有产品API、范围批准、真实head推进或自动恢复，九项范围旗标保持false。清理或最终证据写失败必须同时让报告及Go用例失败。

新47项合成证据模型已由主集成者首次统一实际执行，零跳过／退出0，D:/CodexData/workspace/mihomo-apply-models-actual-j4o2t40k/result.json保留PID、原stdout／stderr、退出和前后源码摘要。检查器明确绑定61源、18公件，新增沙箱网络命名空间与实际进程identity的交叉比较、origin不可能关闭Hijack连接及代理关闭数不得超过真实入口数的约束；对应反例同步篡改报告和journal后仍须拒绝。模型数据明确为SYNTHETIC，不是实际Start／HTTP／业务观测；旧25＋34证据模型的既有结果不替新场景验收。

父db99实际兼容原件另已按44源及1151个Git blob独立复算，报告与producer／fresh逐字一致；D:/CodexData/workspace/mihomo-db99-compat-finalized-63shut5a/result.json。其基础ordinary／race各2项顶层失败及整条CI的failure保持；修正6231584的新CI最近查询仍受API配额限制，尚未读到运行句柄。新实验的实际Linux编译、格式、Start／GET／PUT／本地流量／Wait均须新CI证据，不能由上述源码、既有兼容性或合成模型代证。

以下保留逐阶段事实；实际owned-head首次初始化、产品API与独立批准执行协调器、合法成功的head CAS、零PUT未知对账／恢复、完整异常矩阵和生产灰度仍未完成。本轮不改生产、main或Registry。

### 2026-10-25 最新状态：兼容性真实通过，基础回归仍失败

db99f13的[实际CI 40113825822](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40113825822)已经完成，整体failure。固定Mihomo版本／两份生成配置语法／畸形配置拒绝的compat以及独立fresh均成功；基础contracts及其fresh失败。ordinary／race各290项语义用例通过、209项顶层通过、2项顶层失败、零跳过。失败是旧Store的软链接错误文案兼容和测试把untyped nil的%x标准诊断误当typed-nil Formatter输出。修正保留软链接拒绝及typed-nil隐私断言；没有将原失败重写成通过。

本轮新增源码候选包括：四种固定控制器GET的两轮完整受支持投影读回；可信认证快照／范围RBAC的私有批准关联；固定来源内核的受控进程句柄、输出完整性、监听归属及有界停止；由实际准入工件字节推导预期投影的私有桥。后者拒绝非构造器顺序、重复端点和非规范完整字节。敏感输出对象改为opaque内部指针，避免fmt错误动词回退展开私密字段；同时补充有效批准路径的零PreparedReload拒绝。

这四部分仍是开发源码，不是产品API、真实head、执行许可或运行结果。读回只能比较控制器公开投影，不能证明隐藏的HTTP端点、完整配置、进程身份、数据面或业务可用性；同一投影对应新旧工件时报告AMBIGUOUS。授权检查不能代替最后发起请求时的统一执行守门；内核句柄测试中的自子进程明确是Go MODEL，不冒充实际Mihomo。收据字段全树严格匹配大小写／Unicode规范键；收据自哈希不是发布者签名或生产批准。

新范围保留旧204项强制顶层声明，新增读回28、授权25、Linux进程句柄22、工件桥5，共284项／3包／15测试源；44基础绑定源、55兼容绑定源、39格式输入。25＋34个证据检查器合成模型实际通过。新Go编译、普通／race、实际进程／锁／故障回归尚未运行；不从声明或模型推出通过。已按原CI格式补丁精确转入9份未发生语义变更的旧源，3份正在修改的源没有被覆盖；新源和这3份仍待Linux formatter实际差异。本机未执行Go/gofmt。

以下保留逐阶段历史，发生冲突时以上述最新状态为准。原CI原件及失败摘要位于D盘mihomo-ci-observed-db99-l2nmp_0s；新修正仍须新提交的Linux CI及独立验收。实际唯一PUT、拥有者身份与head CAS、代理数据面／业务验证、异常恢复、产品API／界面和生产灰度均未闭环。

- `internal/mihomodeploy/config.go`：生成完整的受限实验配置。普通选择组、业务候选与域名规则有引用闭包、重复／空池／循环和端口自环检查。字节为私有内容，取出时复制；公开描述、JSON及指针／值拷贝的格式化只输出安全元数据。固定内核的保留名称不能被节点或池覆盖。
- 现有业务草稿不被重写。需要外部控制器承担的切换阈值、回退、会话、能力等要求进入不可变摘要与阻断信息；调用方必须检查 `AdmissionError()`，不能因为静态配置可解析就准入。尚不支持的内核策略或 DNS 配置明确拒绝，未静默转为 DIRECT。现有示例草稿不因此被称为可部署。
- `internal/adapter/mihomo/write_client.go`：与原只读 Client 分开，限定显式端口的回环 HTTP，固定一次 PUT 配置重载，禁环境代理、重定向和自动重放。结果区分未发起、拒绝、确认与未知；204仅是控制器请求确认。它没有批准、备份、读回或回滚的权限证明，错误与调试格式不导出地址、凭据或配置正文。
- `tools/mihomo-runtime-candidate/`：固定官方发布候选的 gzip SHA；离线消费与不导入生产者的独立复算分别检查单 gzip 完整性、上限、实际 ELF、权限、精确源码和确定性收据。发布元数据不是二进制签名，候选没有生产批准。
- `internal/mihomodeploy/artifact*.go`：私有完整工件库保存实际编译输入、完整 YAML 和内容寻址记录；Put 与重开均重建并核对全部字节、长度、摘要和准入。完整旧工件备份绑定操作、设备、代际、内核及进程身份。Linux 路径与文件描述符、私有权限、进程锁、原子索引和目录同步保护写入；同步结果不确定则封闭，缺索引且对象非空时拒绝初始化。9e367已修容量统计的DirEntry.Info工作目录误用，改为实际对象目录的openat／fstat及身份复核。部分真实Linux Go用例已运行，整体验收仍未通过；不等于已经取得设备真实备份。
- `internal/mihomodeploy/plan*.go`：新增不可变实验计划源码，把候选与旧工件、两监听端口、设备范围、代际／head、内核、PID／启动时刻／网络空间、操作及发起者绑定到摘要。审批材料仅核结构和独立声明，不能认证人、授予 RBAC 权限或触发写入。没有 WAL、租约或执行器。
- `internal/mihomodeploy/prepare*.go`：新增PrepareReload源码，在同一私库锁下实际读取候选、完整旧备份和source，重构计划核摘要／时窗与所有目标字段，再比较双方实际控制凭据和监听端口。固定上游payload ApplyConfig不更新ExternalController，故本路径明确拒绝控制凭据变更；不静默忽略变更或输出凭据的单独摘要。返回私有复制正文和安全元数据，不调用控制器、不产生批准、租约或WAL，不证明运行态已匹配。17项新增Go用例已在71fb实际普通／race分项通过，完整CI仍因格式失败。

配置中关闭内建 DNS 不等于操作系统没有 DNS；实验仍须使用回环字面地址和无外网出口的命名空间。配置语法兼容还要由固定真实内核 `-t` 证明，当前源码与模型不能代替。

## 验证方式与当前边界

没有在本机运行 Go、gofmt、实际内核、容器或产品服务。71fbcb8实际普通／race每套150语义用例通过，含109个强制新增顶层用例（写客户端22、配置18、工件与Linux文件系统26、计划26、预备检查17），零跳过。整条CI仍因两份源码的非空gofmt.patch失败；两份实际差异已移入源码，新版完整CI待验。47个候选消费模型及最新版23个Go证据解析模型实际通过，均明确属于合成／模拟；后者绑定18源并要求6份测试源的全部顶层用例，不能以包PASS替代新用例。

首轮实际 CI（dfdd48d，运行40097491560）失败：普通及race均在查找 go.mod 时退出，两个Go事件流均为空，不能算编译或用例通过。实际gofmt输出的配置两文件差异已按原件转入源码。固定候选获取、独立复算及fresh再取成功，三份确定性收据逐字节相同；实际 gzip 22,877,868字节，ELF 62,054,526字节，但内核没有执行、没有签名或生产批准。

修正b0679db已提交推送：保持UID10001、私有网络／挂载／PID空间和只读源码，将模块绑定到私有可遍历别名，临时构建目录为该UID独占；源码摘要、只读挂载与私有目录均在子进程观察，并用严格15项环境清单独立检查。不修改宿主目录权限。原件未记录EACCES，不宣称已经证明最初失败的唯一原因；随后9e367已实际进入Go测试，结果见下。

后续实际CI：9e367d8运行40102862989已读取。普通与race均实际进入Go，每套98个顶层通过、同一个Plan元数据测试失败、零跳过；其中还包括7个原有客户端测试，不能把98误算为本轮新增数。Go事件原件约111KB／套，普通与race退出1且整体gate失败；实际gofmt还有140,513字节差异。失败测试全局禁止`sha256`键，误拒了明确允许公开的嵌套配置摘要；新候选改为10个顶层字段闭集，保留并加强完整私密正文、凭据、URL及编码泄漏负例，未删除原值／指针／空指针保护。此修正尚待新Go复验。原失败及实际格式差异不覆盖，6份实际产生差异的Go文件已按CI原patch精确移入；没有本机跑gofmt。

后续71fb实际运行40104973466中，普通／race进程均退出0，独立复算各150语义用例通过、109项强制新增顶层齐全、零跳过。格式进程也退出0，但产生34,265字节非空差异，故整个合同门与fresh保持失败。两份实际产生差异的prepare源码已按原patch精确移入，没有本机跑gofmt。证据保留于`D:/CodexData/workspace/mihomo-71fb-go-and-format-68wsqp9k/actual-go-subgates.json`，不把分项成功写成整个生命周期通过。

## 本次新增：真实内核版本与配置语法兼容性验收入口

新增Linux构建标签`linux && chengwang_mihomo_compat`的独立测试：固定真实Mihomo版本查询、两份BuildLabConfig实际生成正文的stdin解析和畸形YAML正常拒绝。默认基础门不受标签测试影响。63236a2实际运行40110160604中，基础contracts／fresh成功，普通／race各150语义用例、含109强制新增顶层、零跳过，函数级独立复算与producer／fresh报告逐字一致。

同次真实compat的Go退出0，3顶层＋2子用例通过，4份实际exec记录显示正常启动／等待／预期退出；沙箱及原始流分项已独立重算。完整compat／fresh仍失败：实际38,180字节格式差异，以及检查器错误预期成功提示中的绝对路径。实际输出为固定`configuration file config.yaml test is successful`，此前源码推断的绝对路径已纠正，旧失败不改判。实际格式补丁已移入源码，固定提示／模型已窄修，候选检查函数对四份历史原件通过，但修正后的完整新CI仍待验收；不是实际重载、服务或业务可用性证明。

工作流新增compat及compat-fresh，完整7任务依赖图：固定官方候选先核gzip／ELF与独立收据，再在无外网出口的独立网络／挂载／PID空间，以UID10001、零能力、只读源码和内核副本执行。记录真实启动、Wait、退出／超时／信号、原始输出、stdin摘要和原输入保管。版本查询及语法检查不是服务启动、配置重载、数据面或真实业务验收。

两个随机私密值及两份实际完整输入正文只在私有目录中，用于对公开原始流做编码／正文泄漏围栏。输入缺失、泄漏或不完整Wait／输出不发布伪造空流；失败保留真实安全子集，成功才要求23份公件闭集。独立检查器不导入生产者，绑定29份源码，在fresh任务重算原件并逐字节比较报告；不重跑内核或把历史消费收据的未执行状态改写为执行。

最终独立审查发现Python等值比较会把浮点／布尔值别名当整数接受；旧源实际复现11个浮点反例和8个UID／GID布尔别名被错误接受。两处收窄为规范JSON比较，保留原失败，新增2项类型回归模型。成功行修正后的34项独立检查器合成模型再次通过，19项执行器CPU私有I/O模型原证据保留；这些模型不代替上方真实Linux结果。没有本机下载或执行内核，也不上传二进制、正文或私密围栏文件。Windows本地严格ctime读守门观察到stat／fstat不一致，原失败已留存，未放宽生产检查器；本机只作Git内容绑定与原始JSON函数级复算，不冒称Linux完整CLI。实际内核语法分项成功仍不完成SYS-06。

## 新增源码候选：单记录耐久状态与认证快照

以下为开发提交db99f1327dcd07b3872c9a9408a4e16137a0829b中的源码，尚未取得新范围的实际编译与运行验收，不是已经运行的设备能力。生命周期依然不提供公开Arm／Execute／Bootstrap入口；结构材料和内存owner都不能授予设备权限。

- 私有单一control.json同时记录revision、已声明head、owner／fence、计划、结构批准、撤销、唯一意图、原始请求结果与不可删除的tombstones。CAS要求原记录和精确字节不变，提交后再次完整重读；未知提交使实例失效。重开ARMED／ACK记录转UNKNOWN，不恢复发送能力。只有未发送的三种前置状态在旧owner过期后可取得新fence，保留原计划；任何已发／未知状态不能靠TTL重发。时间回退使当前实例失效。
- Linux后端持固定host全局锁与目录锁，使用dirfd、命名身份、mount身份和私有权限核对；原artifact与新WAL复用一个封闭原子写入器。WAL必须完整写入、fsync、关闭、rename、目录fsync、安全重新打开并逐字节读回才报告COMMITTED；rename之后的任何不确定均封闭。仅有安全既存control时才清理严格归属的崩溃前临时文件，缺control／异常文件保留拒绝。它是同host合作写者保护，不是分布式fencing或防任意同UID恶意操作。
- SnapshotManager每次认证或当前身份查询前，实际稳定读取受信启动路径，沿用唯一凭据解析器；严格规范键、重复键、权限、路径、文件身份、大小和读前后稳定检查。随机manager／epoch结合单调generation；读取、解析或时钟异常立即撤销当前内存引用，恢复旧内容也不复活旧引用。CurrentPrincipal是身份状态查询，不是RBAC决定；与后续外部Do也不构成原子撤销保证。新manager只支持能够实测Linux custody的平台，原immutable Store API保留。
- 格式化边界依据固定[Go 1.23.12 fmt源码](https://raw.githubusercontent.com/golang/go/go1.23.12/src/fmt/print.go)收窄：错误的非指针%p可能绕过自定义方法，因此敏感包装值只含opaque内部指针，普通格式使用value Formatter；特殊类型／地址格式仅保证不展开私密字段，不声称所有格式输出相同。原始持久wire仍只由私有codec编码。

当前增加36项portable声明、22项Linux后端声明、30项认证快照声明，并保留原7项authn测试；合并既有109项，普通／race各要求204个顶层用例，另1个非Linux测试只做源码绑定／格式检查。Go证据模型扩为25项，兼容模型34项；两套合成模型已实际通过，但新Go／文件锁／故障注入／原artifact回归均未执行。CI接线扩至3包、33绑定源、28格式输入；内核兼容独立复算绑定44源，成功23公件／3私件围栏不变。

真实head bootstrap／collector、可信API认证与RBAC批准、manager与WAL身份关联、唯一实际PUT、完整读回／代理业务、自动对账／恢复和产品UI仍待实现；当前codec明确拒绝未实现的成功／readback／recovery状态，不把null或调用者boolean当业务证明。

## 下一步退出条件

1. 将已有实验工件／完整旧备份和结构计划接入目标generation／内核身份、独立可信批准的单一生命周期耐久事务；当前私库不能代替目标运行状态或批准数据库。
2. 单目标租约、写前意图日志、超时未知结果的只读对账，禁止盲目重试。
3. 两个隔离真实内核的校验、灰度、实际配置应用、规则／组／连接和本地真实代理流量对证。
4. 故障后的精确旧工件恢复、再验证，以及控制面／内核重启后的恢复或人工接管。
5. 范围 RBAC、产品 API、真实操作页、审计记录及独立证据复算；旧 local_record_only 操作 API 不被解锁来假装设备执行。
6. 完整策略语义、外部能力要求执行、其他协议与内核适配、正式镜像／Registry／签名策略、企业生产权限和真实环境验收。

本轮无生产、main、Registry 或正式发行变更。后续生产灰度仍须前置验收、备份、回滚和单独明确授权。

## 2026-10-25：已核正常发布链路与新增 UNKNOWN 故障验收

正常路径的实际接受基线是提交 `2766971bcd4d44f5d79c0edbdbff04f580cd4c06`、Linux CI `40137507621`：11任务全部成功，普通／race各879项唯一语义测试通过、407项必需顶层逐项齐全，零失败／跳过。服务58份公件、32份原始GET正文、11次产品HTTPS、实际Reload／Do计数0→1→1及5个端口真实拒绝均由原检查器和三路独立复核确认；5对producer／fresh报告逐字节一致。源码1213个Git blob、10个ZIP的146成员已保管。该结论只适用于固定双配置、局部真实代理路线和正常批准发布，不证明故障恢复或全网业务可用。

本次新增单独的 `unknown`／`unknown-fresh` 开发分支CI入口。显式实验标签下，原生HTTP Transport先实际调用固定内核，观察真实204、零正文自然EOF及成功Close后，再让客户端丢失响应；原写客户端必须实际得到unknown／dispatched=true／status0。故障胶囊的204观察与客户端UNKNOWN结果分开保存，不能据此完成原操作或解锁写入。默认构建仍返回同一个原生Transport，实验不能由环境变量或HTTP请求启用。

新实际产品测试通过14次HTTPS检查独立批准、UNKNOWN状态、候选已更新但旧head仍为generation1、原始transport结果及耐久观察、重放和再次创建不增加请求。被阻止的新建复用原候选，避免“同配置本来就拒绝”的空验收。4阶段原始采集、故障观察、Go事件、源绑定、退出及5端口清理均由独立新检查器核验；采集器不生成旧positive报告来骗过原检查器。新入口的源码或合成模型通过不构成新Linux实测通过；必须取得同提交的真实原件与fresh结果后另行记账。

新epoch恢复仍未实现。即使候选读回稳定，也不得自动重发、清除UNKNOWN、篡改旧结果或把JSON/PID当能力。下一恢复阶段必须有单独批准的目标完整工件、原owned进程实际Stop／Wait／stream／group／监听关闭、新epoch实际启动与验证、旧未知事实保留及耐久head提交；控制面丢失原句柄的场景需要另设可信supervisor边界。完整故障矩阵、恢复自动化、多内核、DNS、业务分流、企业治理、全功能UI、容量／浸泡、灰度和生产读回均未完成。

### c9167f 首次实际 UNKNOWN 运行：产品实验成功，格式门使整 CI 失败

提交 `c9167f3299bbe438cfc945caff5d16e906a1f6d3` 的实际运行 `40140626055` 已终结：13任务中9成功、4失败。新增UNKNOWN的真实Go进程退出0，原报告PASS，58公件齐全，实际14次HTTPS和32份GET正文保留；原生Transport的真实204／零正文EOF／成功Close观察与adapter的unknown／dispatched=true／status0分开。旧head为generation1，耐久原transport及一次观察保留，replay／新建后原WAL与0→1→1→1计数不变，关闭返回与五端口拒绝均有原件。Go事件有33项胶囊MODEL语义和1项真实产品顶层实验；不能把33项模型称为33次真实业务验证。

整门没有通过：实际gofmt产生58,029字节差异，foundation／UNKNOWN及各自fresh均失败。独立复核确认原未改checker拒绝；另副本仅排除这一项空格式约束并将原PASS返回替换为诊断检查点后，抵达其余原语句的返回前，不执行或构造原PASS。因此该诊断不等于原检查器通过。四份实际formatter补丁已严格按c9167f原Git preimage转入源码，foundation与UNKNOWN两份补丁派生结果逐字节一致；没有本机执行gofmt。修正版必须再次真实CI验收，原失败不改判。另加强三个既有负例，让after／replay／final一致变异，直接检验durable attempt／transport／observation门，避免只被前面的快照不一致检查拒绝。

### 2bba397 修正版：UNKNOWN零重发隔离验收通过，整套系统仍未完成

实际接受源码固定为 `2bba397183464e456a62184e11a674405df7402e`。GitHub push运行 `40141260943` 的13任务全部success；12个原ZIP的208成员按API摘要、CRC和逐文件SHA保管，精确源码1227个Git blob已核。Foundation普通／race各879唯一语义run／pass、407必需顶层逐项齐全，零skip／fail，格式与stderr空；正常service、apply、compat、candidate及新增UNKNOWN均由原验证器与三路独立复核重算，六组producer／fresh报告逐字节一致。

新增UNKNOWN原未改 `check_unknown.verify_raw` 对58公件完整返回PASS，无AST例外；32份GET正文、14次HTTPS、33项胶囊MODEL语义与1项真实产品实验、实际204丢响应、客户端unknown／true／0、旧head generation1／写阻塞、原WAL及0→1→1→1计数、真实清理与五端口拒绝均有原件。底层控制器收到次数仍为null，不把Transport调用次数冒充该值。本机纯raw报告保留 `sourceGitVerified=false`，两份实际LinuxCLI报告为true；只在独立比较副本核其余字节，不修改原件或冒称本机LinuxCLI执行。

统一实际收据见 `evidence/sys06-unknown-acceptance-2bba397-20261025.json`。该接受只覆盖固定双配置的正常链路及显式响应丢失UNKNOWN不重发实验；旧c9167f失败保留。完整中断／撤销／到期／崩溃矩阵、独立预批准的新epoch恢复、完整私密载荷／WAL及持密围栏独立证明、互联网业务、DNS、多内核、企业治理、真实UI、容量／浸泡、整套恢复、灰度和生产读回均未由此证明。本次只归档文档与证据，不改已验收的产品源码，不触碰生产、main或Registry。

## 独立恢复底座：源码与CPU检查完成，新的Go验收尚待执行

新增专用恢复RBAC、结构计划、原owned进程quiescence证明和独立v3日志／耐久启动前缀。五个恢复动作固定完整lab范围，写动作强制critical、双人批准且禁止BreakGlass；这些策略本身不认证用户。结构计划绑定原UNKNOWN及其原始record／plan／intent、旧epoch、目标完整工件与固定预算，允许选择旧工件重新启动epoch，不把旧请求改为ACK。v1/v2默认codec、genesis和磁盘实现保持原字节，v3只由显式受控演进路径使用；原v2完整私有control内联保管，不启动自动迁移或删库。

新quiescence helper只操作原owned Process，支持仍持原能力时的自然退出；真实Wait／EOF／group及两个固定端口拒绝后才能签发一次性事实。原writer仍全量hash并drain日志、仅截存前64KiB，新证明因此区分CAPTURE_LIMIT_ONLY和未排空；旧stop错误与严格合同不改，不把截存称作完整原文证明。新record-only消费保留晚到的原签发事实，当前过期则保持UNKNOWN且不授Start。v3 store只有实际q来源经耐久记录及START_ARMED精确读回后才产生一次性结构启动许可，重开不从JSON恢复能力；opener显式接可信now，时钟回退拒绝。这里仍没有新的内核启动或成功head工厂。

本次新增86项Go MODEL测试声明；CI目标6个包／37测试源／99格式输入，全部514项必需顶层（含原407和首次纳入此门的21项既有authz顶层）都有冻结名单与摘要。原407名称另由 `legacy_go_tops.json` 按已接受2bba源码固定为不可删除子集。137源的独立UNKNOWN绑定及其他层计数同步扩展。262个Python合成检查模型实际通过，但这不是新增86项Go已编译／运行的证明，仍须同提交真实Linux普通／race／格式与原件复核。

完整恢复仍未实现：真实SnapshotManager恢复authority、闭合LEGACY/V3 journal facade、唯一新Start、专门恢复collector、实际新head与后续普通发布、API/runtime接线和真实恢复E2E／全故障矩阵必须继续。当前对外不打开恢复路径，不把结构许可当用户批准，不把源码或模型当生产可用。本轮仍无生产、main或Registry变更。
