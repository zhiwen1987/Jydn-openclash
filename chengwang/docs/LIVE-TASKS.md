# 澄网：项目任务清单

固定来源候选冻结与单一集成（2026-10-26）：基2eb的14源补丁已获implementation与policy独立source允许，单一集成器及输入清单的v3复核亦允许进入实际stage。新raw事件与legacy四字段DTO分型，三个显式Kill调用点经六个固定hook记录来源，continuous投影同锁逐项对应；nested response-loss v2／outer report v3／contract v2，HTTP index v2。continuous格式19／delivery33、profile单项4／完整28按原清单精确插入三个既有Go源；旧job-owned格式子集与OLD_V5/BOUND pins不动。worker三条隐私函数原字节不变，safe_report_outputs仅固定schema更新；kernel六处hook名称反向替换后整文件等于2eb，OS行为／锁／授权未改。仍须统一提交后的303项CPU、两个源码绑定、新Go/gofmt、31HTTPS/端口清理/fresh和所有旧链回归。普通race180秒问题及性能稳定收益未证明；高风险prefix优化未实施，独立-p1诊断候选仅在复审，不取代原验收。

2eb补验及修订决策：首次Completion四模式9 ZIP／167成员已[独立接受](evidence/sys06-2eb-first-completion-original-audit-20261026.json)，不抵消continuous或normal拒绝。[P1源码复盘](evidence/sys06-2eb-cleanup-source-postmortem-20261026.json)及[旧review勘误](evidence/sys06-2eb-cleanup-review-erratum-20261026.json)已保留：旧5904种排列只验证了自设偏序，不能证明它涵盖真实cmd.Cancel路径；旧source允许结论按此纠正。下一候选采用source-owned固定来源的CANCEL/STOP/IDENTITY kill观测，raw与legacy DTO分型、同锁逐项投影，continuous nested observation v2／outer report v3／contract v2；旧wire、31 HTTP、CASE_ACTOR、private inventory与fence不得被任意改写。仍仅证明已插桩源码调用，不承诺覆盖Go WaitDelay内部所有OS调用。此候选正在外部实现，尚未集成／Go运行；高风险history-prefix复用仅完成可行性调查，未实施，不声称修复性能。

2eb实际原件更新（2026-10-26）：[continuous原件](evidence/sys06-2eb-continuous-original-rejection-20261026.json)整体拒绝；两组MODEL各27／9／6名称均实际run/pass，31 HTTPS全成功且errorClass NONE，但Go top在CLEANUP_CALLS失败、port probes尚未执行、verification/fresh为空。公开末尾6事件是同一finalCore的KILL_ATTEMPT→HELPER_ENTER→KILL_RETURN→TERM_ATTEMPT→TERM_RETURN→WAIT_RETURN；lab_kernel另有cmd.Cancel kill路径，旧P1把其与stop升级kill混为一条串行路径，正在根据真实源码和Go1.23.12重新定义并发验收合同，不放行FAIL原件。[normal/diag/UNKNOWN](evidence/sys06-2eb-normal-diag-unknown-original-audit-20261026.json)：UNKNOWN实际Go／格式／原checker／fresh均接受，43／30模型通过；diag single/full原件与fresh接受，full实际688必需／2004 semantic通过、主包124.48秒。normal ordinary接受688／688，但race180.048秒超时：587通过／1未完／100未开始，整体normal拒绝，不能用diag成功抵消。性能稳定收益及唯一资源原因仍未证明。[oldnative S2](evidence/sys06-2eb-oldnative-original-audit-20261026.json)四模式9ZIP／192成员另有限接受；首次Completion仍待本HEAD原件复核。生产、main、Registry均未动；下方in_progress为此前快照，按本条更新。

最新开发提交：`2eb7717a7a9d32308fbb90c45b2c183c1acb53d8`（2026-10-26）。24路径已提交／推送／远端精确读回，root完整303项CPU及native/continuous最终HEAD源码绑定复演通过，独立快照1516个Git blob逐字节核对；原工作区HEAD及3个用户文件未改变。新HEAD五套CI已实际进入in_progress：continuous40320476780、normal40320476704、diag40320476723、oldnative40320476761、firstCompletion40320476659；这些是运行中状态，尚无本HEAD运行验收结论。UNKNOWN强门43／30、final第二恢复core清理增强和exact revoked-tail复用均已纳入源码；性能收益、Go/gofmt、完整31、fresh及180秒稳定余量继续待验。生产、main和Registry未动。以下“下一开发集成”为提交前的计划记录，1c接受仅适用于其原件。

下一开发集成（基1c1fa28，2026-10-26）：三项独立source peer已允许进入新Linux验证；统一7个源路径修正UNKNOWN闭集43／30和本地名单回归、第二恢复finalCore的清理基数／偏序，并只复用同一次完整校验中已经验证且逐值相同的V1 revoked history尾项。性能v1负例矩阵不足及later-schema夹具先退出已保留并由v2补齐；不删除原688名称，不改180秒、256轮、2MiB或private fence。拟运行303项CPU、源码绑定及新HEAD实际Go／gofmt／31链／fresh；本条仅记录源码集成目标，不代表这些新HEAD运行门已经通过。性能收益和完整race超时修复尚未证明；以下1c原件接受只适用于1c。

同HEAD旧链补验：`1c1fa28`首次Completion的9 ZIP／167成员、四模式原checker／fresh字节一致已独立接受；oldnative S2另9 ZIP／192成员、四模式checker核心函数链与Linux原verification／fresh字节一致。oldnative本机完整main受POSIX报告写出路径影响曾拒绝，接受仅基于未修改核心函数链复算，不冒称该main在Windows成功。两条链分别限定其场景，不互相代证；见[Completion](evidence/sys06-1c-first-completion-original-audit-20261026.json)与[S2](evidence/sys06-1c-oldnative-original-audit-20261026.json)。

最新原件验收（2026-10-26）：开发提交 `1c1fa28533d8582e874a1552d5166a271f0727b7` 已推送，root 302 项 CPU 与 source replay 通过，独立快照 1500 个 Git blob 核对。continuous run40315107960 的两组 Go MODEL、实际 31 HTTPS、原 checker 和 fresh 原件已独立接受；root 再执行原 checker，核对 verification/fresh 原字节一致（871 字节），并重算 normal/profile 原件。限定链为 UNKNOWN→恢复→普通 ACK→第二 UNKNOWN→第二恢复；不证明完整私有 WAL、公网业务或生产。Normal ordinary/race 各1992项通过、688必需、格式干净，race包148.35秒；full诊断的25项格式清单已闭合，但Go仍180.052秒超时：585通过／1未完／102未开始，容量top86.54秒通过不能抵消总失败。full-fresh只证明诊断捕获复算成功。UNKNOWN的43项证据模型和29项泄漏模型实际全通过，workflow仍固定旧28项与旧摘要，实际worker未运行；已定位清单守门缺口，不能称产品UNKNOWN失败。旧native/首次Completion的新HEAD原件另核；P1清理归属增强和性能窄候选另行复审，不把未集成候选算完成。原件与root复核中的Windows输出换行／timeout字段形状两次协调器错误均保留，不改CI原件。生产、main、Registry未动。

两项合同修正冻结候选（2026-10-26）：PASS/PASSTHROUGH不观测body读取／关闭，checker改为三项必须null；两LOSS仍严格int0／true／true，拒伪填PASS与LOSS空值／别名，其他31业务、HTTP原字节、source及双fence不变。6d实际报告的纯validate_report复演31通过，33个聚焦负例拒绝，仅为DIAGNOSTIC_READER_LOGIC_REPLAY_NOT_EXACT_HEAD_ACCEPTANCE。另profile producer按独立checker完整顺序补齐25个格式源，新增2个真实argv捕获CPU合同测试和CI前置依赖，180s／256／2MiB未改。两个候选共5个源码路径，不改Go运行语义；待root统一提交后完整302项CPU与新Linux31／fresh。6d normal原件现已独立接受：ordinary/race各1992／1992、688必需、fmt空、race119.437秒；single profile仅诊断接受。full profile仍先拒producer20/checker25，隔离该差异后实际Go180.049秒超时，579通过／1未完／108未开始；容量top89.08秒自身通过不抵消总失败，性能根因仍未证明。生产、main、Registry未动。

6d772开发提交与独立检查器失败（2026-10-26）：提交`6d772592ae103083f52dc3ace21c5ffd695f0e56`已推送并经远端精确读回；root同HEAD完整11模块300项CPU检查、两个source绑定复演通过，独立快照1488个Git blob核对。continuous run40310535727的fault MODEL121530401827与bound MODEL121530402013均终态success，原件独审尚在进行；HTTPS121530713973的实际执行／导出step7成功，但原checker step9失败，fresh121531227593 step4也失败，尚不能称完整31链被接受。首次Completion40310535601与oldnative40310535630仅核到任务success，未代替新HEAD原件审计；normal40310535603失败，diag40310535495另核。本轮安全artifact helper已通过源码复核且对上一HEAD三个原件受控下载成功：真实凭据与302链接仅在同一进程内，禁止旧curl URL参数／session检索；已披露的旧通道缺陷与历史URL回显不因此抹去。生产、main、Registry未动，整套系统仍未完成。

767后续六文件冻结候选（2026-10-26）：测试夹具明确设置并核验0700目录／0600凭据文件，保留0755／0644拒绝负例；RunWith夹具补正必需监听回调与正超时，要求只到TLS失败、监听回调不可触达，并保留manager关闭／不可重arm断言。完整吸收实际Linux Go1.23.12生成的3213字节／3文件格式补丁；尚未把新候选称为最终格式为空。OLD_V5旧五元组原样保留，源码固定active完整新五元组，只更新两枚已审兼容工具指纹，禁止历史fallback／逐文件并集／混搭；新增独立Python回归top。两份独立源码复核允许单一集成后进入Linux，11模块300／300 CPU通过。实际authn上次内部细因仍未唯一观测；不能用源码夹具修复代替新Go结果。生产、main、Registry未动。

767fa9开发提交与新Linux失败（2026-10-26）：最终提交`767fa9a29b50b761e84fe654a829e1d47f74ac4f`已推送且远端读回一致；root同HEAD完整11模块299项CPU检查及两类源码绑定通过，独立快照1480个Git blob核对，原工作区HEAD及3个用户文件保留。continuous run40305246343的旧fault MODEL父项+5子例独立原件接受，前后source绑定完整；新bound MODEL job121512741501实际已编译运行但失败：authn直接8子例2过／6失败，首例只给ErrSnapshotUnavailable；runtime直接4子例3过／1失败，首拒CLAIMED_MANAGER_NOT_RETAINED，两包stderr空、exit1，失败导致after-source缺失，不能称双绑定。源码确认两个fixture前置缺口：authn TempDir未显式保证0700；runtime RunWith Options缺Listen与正ShutdownTimeout，必在claim前返回。前者仅为确定配置缺口，实际细因被折叠，不能称唯一原因。HTTPS job121513004403跳过，fresh缺件次生失败，本提交未执行31链。旧native正例原件实际Go0／PASS，但官方gofmt.patch非空3213字节／3文件，不能接受；首次Completion在Go前SourceCheck被OLD_V5两枚过期工具指纹拒绝，Go未执行。指纹将按历史受控迁移语义保留legacy完整五元组、源码固定active新完整五元组，无逐文件历史并集或fallback。以上修复尚待新源码及新Linux；normal/diag其他原件另审。生产、main、Registry未动。

旧链闭集修复冻结候选（2026-10-26）：以本地eb028为基，8个Python文件的最小修复已完成；兼容／apply／service／unknown的精确继承成员数为162／170／177／183，service格式源8项、unknown11项，apply1项、continuous delivery30项保持。两个新增格式成员回归测试如实纳入全11模块，独立299／299 CPU通过；仍须root单一集成提交后的同HEAD复演与真实Linux。没有新增Go运行证据；公共运行证据不记录argv，因此格式成员仅由source-bound producer与CPU精确tuple检查支持，不冒充独立运行时argv观察。旧85项的4ERROR及此前闭集审查遗漏／纠错链保留，不改判。生产、main、Registry未动。

eb028本地集成回归（2026-10-26）：已生成本地开发提交`eb028fe90aeae56cc66fefeb4fde4a06052cc747`，快照1475个Git blob核对；尚未推送，远端仍是6e309。完整集成门在apply/service模块的85项检查中实际81通过／4ERROR，首门是两检查器仍沿用旧源码闭集计数（apply167、service174），而真实继承成员已是170／177；不是Go或真实HTTP失败，因为本提交尚未进入Linux。横向复核另发现service及unknown的格式源清单需包含本轮修改的实际默认构建成员。正在准备独立最小修复，并把CPU回归扩到全部11个本目录测试模块；不得修改旧结果、删除新源或放宽校验。原本地提交、失败原件和文档空格修正的首次集成失败均保留。生产、main、Registry未动。

bound-credentials v2冻结候选（2026-10-26）：26路径／3个新增Go文件的外部源码候选已完成，独立94项CPU检查通过，认证与闭集两份现存哈希匹配复核记录允许单一集成后进入Linux诊断。新版仅在exact tag与一次性source arm中激活，私密文件只含凭据、公开授权绑定来自源码闭集，API Store与SnapshotManager初始同源；真实认证、v1解析核心、原始31HTTP映射、private inventory及双fence保留。显式null／错类型在v2拒绝，旧v1行为仅为兼容意图，仍须真实回归。新Linux Go／gofmt／两个专用MODEL／完整31 checker与fresh尚未获证；共享产品源码确已改变，生产环境、main、Registry未动。下面6e309及更早条目按各自提交保留，不代表本候选已完成运行验收。

6e309开发集成与实际验收（2026-10-26）：CASE_ACTOR v4已纳入开发提交`6e309c4d150b6f9248089ad50abf3ede9015784c`，13路径提交与远端读回一致，179项CPU检查及两类最终HEAD源码绑定复演通过。独立快照1463个Git blob逐字节核对。[MODEL原件审计](evidence/sys06-6e309-model-independent-audit-20261026.json)已接受主测试和5个子例各run/pass一次、无fail/skip、exit0、stderr空与前后source绑定。continuous run40294370287的真实HTTPS job121477086646及fresh job121477467062均失败；[安全诊断原件](evidence/sys06-6e309-continuous-safe-rejection-20261026.json)显示Go exit0、31HTTP、report PASS、末SECOND_RECOVERED_HEAD 200/NONE，但report/original fence因IDENTITY_PROFILE/JSON_OTHER_SCALAR/RAW拒绝导出。公开fallback没有report、HTTP、Go事件或gofmt.patch，不能独立证明31链或空格式补丁；checker/fresh是缺件后的次生失败。Create计数4是两次Create的ENTERED+ACCEPTED共4阶段事件，不是4次Create。源码独立证明至少一个必然冲突：private authn profile复制公开LabObjectType，而必需API schema含同一片段，全scalar RAW子串扫描必拒；没有读取或识别实际首命中私值，不称唯一运行时原因。下一设计改变输入边界：bound-credentials v2只在私密文件保留凭据，公开授权绑定由isolated-only源码闭集提供；此方案尚未实现，v1、真实认证/RBAC、HTTP原字节、全私密输入与双fence均须保留。生产、main、Registry未动；下方按提交保留历史结果。

d586实际分层验收（2026-10-26）：Go MODEL父测试与5个子例共6个源码绑定事件均run／pass，零fail／skip，package PASS、exit0、stderr空，source-before与source-after原字节及独立快照重算一致。实际HTTPS的安全诊断显示31请求、Go exit0／report PASS、末SECOND_RECOVERED_HEAD HTTP200／NONE、两次Create阶段均ACCEPTED；这证明执行器报告已走完整链，但不代替独立原件验收。隐私fence仍因报告重复公开VIEWER角色的JSON_QUOTED形式而拒绝导出，因此原checker／fresh未接受，完整场景整体仍未通过。下一源码方案只把报告／index改为固定CASE_ACTOR场景枚举，真实token／request role／authn／RBAC不改，禁止对私值Upper或任意编码，unknown在发请求前拒；private inventory、8变体、双fence及诊断自身检查必须原字节保持，不做角色例外或结构mask，真正secret与枚举碰撞仍须拒绝。当前31为正授权链，角色viewer12／admin10／approver5／auditor4、operator0，状态5×201＋26×200，不能据此称401／403已验收。本轮已纳入CASE_ACTOR报告/index v2候选源码，仍待新exact-head Linux原件；v1至v3复审拒绝均保留，v4恢复有界失败取证并固定独立31表，FAIL原件从不作为成功证据，生产、main、Registry未动。

273真实MODEL与端口修正（2026-10-26）：Go已实际编译且进入目标top，但parent run／pass／fail=1／0／1；stage子例通过，新增四个second-recovery子例均在MODEL ordinary plan处失败，无skip，HTTPS因此跳过。实际日志未给PlanError.Code；源码独立确认recovered head端口为28412／28411，而fixture默认candidate为19090／18080，违反未改动的NewPlan端口门。当前只修测试helper：candidate与backup两个按值spec均在Build前绑定current head端口；backup只Build一次，先显式核其Config SHA等于head artifact，再把同一bytes交Prepared。合法actor、regexp、原全部断言、MODEL top、31 HTTPS、权限与产品逻辑不改；错误仅输出五类封闭PlanCode或UNKNOWN。新exact-head Go MODEL尚未运行，不称已通过；必须先MODEL真实全事件通过，再验完整31 HTTPS及原件checker／fresh。ROLE例外仍未实现；生产、main、Registry未改。

505实测与MODEL编译修正（2026-10-26）：normal普通／race各1992语义、688必需通过；diag single及full原件均通过，full包128.994秒；首次Completion四模式9 ZIP／167成员／1443源限定通过。上述都不代证连续恢复。连续run40280615306在Go MODEL进入前因TYPE_MISMATCH编译失败，目标run／pass／fail均0，HTTPS按前置门跳过，fresh缺原件属次生失败。安全定位为test源码171:109：基础lifecycleModelDisk不满足labRuntimeDisk。当前仅修测试，复用既有labBootstrapModelDisk，并让strict reopen、recovery、handoff、runtime保持同一wrapper身份；底层writes／state／writeErr故障断言不变，增加编译期接口断言，产品transition／owner／fence及31请求链不改。手工MODEL owner／handoff仍不是真实Completion或冷开权限。必须先由新exact-head Linux MODEL真实run／pass，再验收完整31 HTTPS、原checker与fresh。ROLE例外仍未实现，503修复效果尚未获证；单样本性能通过不代表稳定余量，生产、main、Registry未动。

9fac实际验收与源码阻断（2026-10-26）：普通／race各1992语义、688必需通过，race包149.284秒；首个Completion四mode的9 ZIP／167成员／1434源经原checker与fresh限定复核通过。diag single通过，full仍在180.051秒超时，未证稳定性能余量。新增fault Go MODEL已从NOT_RUN转为真实RUN_AND_PASS，前后源码绑定一致。连续HTTPS仍于HTTP26 SECOND_RECOVERY_CREATE返回503／NONE，固定诊断为REJECTED_BEGIN；stateMayHaveChanged是保守分类位，不证明WAL已写。独立源码审查确认：terminal执行事实非空，而fresh PLANNED为空，通用Execution相等早门先于合法终态替换分支，足以阻断该路径；这不代表诊断已证明运行时唯一原因或修后无后续缺陷。修复必须保留旧完整terminal history tail、只准新鲜PLANNED且无执行事实，并保持owner／clock／CAS／full validation／publisher各门；完整31链、第二恢复及安全原件导出仍未通过，ROLE例外未实现。性能V3仅在独立886e154分支实测，run40275513837四leg均180秒包超时，容量target通过不代证完整接受；候选未纳入主生命周期分支，亦不能归因顺序／profile／host。8子代理与主会话共9个running已由实际列表验证，不是配置推断。下载时一次临时签名链接被TTY工具回显，进程已终止，去敏事故保留，未将链接落盘；后续只准非TTY隐藏输入。生产、main、Registry未改。

567原件与第二次恢复诊断（2026-10-26）：normal ordinary／race各1992语义、688必需且零fail／skip／unfinished通过，race包121.681秒；diag single／full原件通过，full包147.558秒；首次Completion四mode9 ZIP／167成员／1426源经原checker与fresh限定复核通过。不能由单样本证明性能已稳定。连续run40250192418推进到HTTP26 SECOND_RECOVERY_CREATE，实测503／error NONE，Go以HTTP_RESULT失败；此前ACK合同错误已越过，但第二次恢复未完成。两次独立源码调查都未唯一定位内部503分支，未猜修、未放宽UNKNOWN或授权门。下一源码仅添加source-issued同service、最多4事件的固定阶段诊断，默认构建空实现；共享backend确有marker源码改动，不等同于零源改动，业务语义意图不变仍需Go／Linux验证。诊断只输出固定enum和实际HTTP envelope的严格stateMayHaveChanged布尔，不输出error／opID／hash／path／body；ROLE例外未实现。发现fault Go MODEL之前未由现有CI执行，状态为NOT_RUN而非FAIL；新增独立exact-tag MODEL job并作为实际HTTPS实验前置，原serverruntime单TOP与31链保持，delivery闭集24→25、format10→11同步。配对测量在独立8d360ed分支run40252034807已实际完成并复核：AB两leg接受、BA两leg均180秒超时，虽然两job都success；不能归因于第二位置／profile／负载／源码收益。原件结构接受不代替Go接受。新诊断源码、Go负例与真实连续链仍需exact-head Linux验收；生产、main、Registry未改。

a034实际结果与ACK合同修复（2026-10-26）：首次Completion四mode的9 ZIP／167成员／1422跟踪源经原checker main及fresh逐字节复核限定接受，其他API链不由此代证。normal ordinary1992语义通过，但race1686通过后在180.047秒超时，容量top已84.89秒通过，未完成为VerifiedBoundsCoordinatedTamper父测试及recorded-before-marker子例；diag单例通过，full1680通过后在180.042秒超时，未完成为同父测试及source-owner子例，容量已85.75秒通过。所有失败原件保留，不把零terminal失败当全套通过，不作跨模式性能归因。连续run40248700273已到第19项ORDINARY_ACK_HEAD，实际HTTP200／error NONE，随后Go以ACK_HEAD失败；具体五项中哪项失败尚未直接观测。源码确定普通ACK完成后保留terminal Active并由Head返回同operationID，测试错误要求nil；下一源码修复要求非空且精确等于本次ACK operationID，并保留generation+1、headSHA、candidate artifact、unblocked及COMPLETED／HeadAdvanced／204／真实observation严条件。reader与MODEL同步，nil和foreign ID负例拒绝，产品源码不改。安全诊断已确认IDENTITY_PROFILE／JSON_IDENTITY_ROLE／公开VIEWER／JSON_QUOTED匹配，仍在任何导出前拒绝；结构化角色元数据例外仅为设计附件，未实现。AB／BA配对测量候选已源码复审，尚未Linux测量；不能声称同负载、因果收益或产品接受。新ACK源码仍需exact-head Linux验证；31请求及第二恢复未完成，生产、main、Registry未改。

f9实际结果与HTTP6源码修复（2026-10-26）：首次Completion四mode的9 ZIP／167成员／1418跟踪源经原checker main及fresh逐字节复核限定接受；普通／恢复API、第二恢复及完整私有WAL不由此代证。normal本轮原checker拒绝：ordinary 1992语义通过，race1921通过／零terminal fail／零skip，在180.039秒超时；容量top已79.98秒通过，尚未完成的top为TestLifecycleV3SourceSnapshotRejectsHashSchemaMarkerAndRewrittenFacts。diag单例与full本轮原件都通过，full1992语义／容量53.71秒／包125.537秒；不抵消normal失败，也不归因代码性能收益。连续run40247242017已越过初始WAL检查，安全诊断观察format0／Go1／HTTP6／HTTP_RESULT；按固定顺序第六项为FIRST_UNKNOWN_INSPECT。actual status尚未安全观测，不能把源码推断的403当实测。产品通用ActionReadResource不允许auditor，最小源码修复只把普通deployment inspect改viewer；专门recovery读门允许auditor，保持原角色，产品RBAC不改。第一report fence因IDENTITY_PROFILE／JSON_OTHER_SCALAR／JSON_QUOTED在任何导出前拒绝，实际源元素仍未确认，无公开泄漏证据。下一诊断仅增加精确角色来源与最后HTTP固定事实，仍不豁免任何匹配；31请求、UNKNOWN／ACK／两次恢复验证不缩减。新源码仍需exact-head Linux验收，生产、main、Registry未改。

54dc实际验收与下一源码修复（2026-10-26）：normal原verify复演通过，ordinary／race各688必需、1992语义且零fail／skip，格式为空，race125.327秒；首次Completion四mode的9 ZIP／167成员／1414跟踪源也经原checker main及fresh逐字节复核限定接受。diag单例通过，但full在180.049秒超时，唯一未完成top为容量／revision reserve；不把跨模式耗时差归为优化收益。连续run40245238037已真实编译进入Go且观察到runtime listener与hook，formatExit=0、goExit=1、HTTP=0、failureCode=INITIAL_STATE。安全fence在任何导出前拒绝continuous.json中的IDENTITY_PROFILE／RAW变体，未证明公开泄漏或误命中。已定位harness、reader和MODEL共同漏写WAL标识中的-record；下一源码修复以真实product const为权威并加入旧错值负例，不改产品WAL或decoder。安全诊断扩展须同时覆盖报告初扫与最终全输出扫描，只允许固定来源类别，不豁免任何匹配。新源码仍须exact-head Linux取证；真实恢复API、恢复后普通发布、第二恢复、完整私有WAL及整套系统仍未验收；生产、main、Registry未改。

本轮810b验收与后续诊断源码（2026-10-26）：normal原verify直接复演通过，158源、ordinary／race各688必需与1992语义、报告byte-equal；首次Completion的9 ZIP／167成员／1407源也经四mode原main与root原始计数复核限定接受。两类接受只针对810b，不代表恢复后service rebind、产品恢复API、普通发布或第二恢复。diag full仍180.049秒超时。连续实验因全输出secret fence拒绝导出，原件未公开Go退出／HTTP结果。当前仅worker+MODEL两源补充安全诊断，并关闭REPORT缺失时未构建inventory的继承旁路；无实际泄漏证据。6类输入／8种编码／最小长度8／导出前拒绝保持；诊断只允许固定类别、阶段、退出码、计数和39个已知Go失败码，未知值映射UNKNOWN，诊断自身再次过同一fence，命中则固定拒绝。模型覆盖REPORT缺失且输出含私密值时write_new=0。没有修改Go、预算或生产，下一exact-head Linux诊断仍需实际执行；不把候选、诊断投影或其他成功门当连续恢复通过。

最新810b核对（2026-10-26）：提交`810bce48cd40a38a3703c068eeb49583d68c485e`已推送并经认证GitHub ref读回一致；最初Git CLI读回连接超时单独保留。normal run40241633602及fresh成功，原`check_contracts.verify`由root直接复演（无适配、无证据替换），158源、ordinary／race各688必需与1992语义通过，报告逐字节同CI；格式差异为空，race149.21秒。diag full仍在180.049秒超时，不能宣称稳定性能余量。旧S2与首次Completion新CI状态成功，完整原件复核另行记账。连续恢复run40241633594已过Linux模型阶段，但在通用输出secret fence阻止导出；原件缺Go退出与HTTP报告，结果仍未证明。仅增加非敏感碰撞诊断的候选正在独审，原泄漏拦截保持。生产、main、Registry未改，整套系统仍未完成；下方旧记录只适用于各自提交。

最新97fa原件核对（2026-10-26）：normal普通／race的原事件检查器子门均688必需、1992语义通过、零skip；race包128.838秒，新增owner对照子例真实通过。原完整基础门仍因19882字节非空官方格式补丁失败；同提交diag full又在180.053秒超时（587通过／1运行中／100未起），不宣称稳定性能收益。continuous首轮在Go前的两个CPU模型因未模拟root文件归属而错误，实际Go／HTTP未进入。当前仅精确移入实际Linux Go1.23.12格式补丁的3源／15hunk，并修MODEL fstat仿真一源；生产worker UID/GID0、nlink、size及路径门逐字节保持，非root负例仍拒绝。旧S2与首次Completion只核两份positive：真实Go均通过，原reader均拒绝相同格式差异；内存替空格式的检查仅为诊断投影，不是原件接受，其他6个模式不外推。修订后仍需同提交Linux CI；产品API／连续恢复与整套系统未验收，生产、main和Registry未改。

本次源码集成（基3c6d456，尚未Linux验收）：按冻结清单合入连续HTTPS链与兼容闭集37路径，并只修复N3对照MODEL缺RecoveryOwner前置的一份测试源；源审通过不代表Go／HTTP已运行。计划链为真实UNKNOWN→恢复→普通ACK→第二UNKNOWN→第二恢复，共31次产品HTTPS调用；目前仍为待运行计划。基础源码158／必需测试源58／完整格式源152，688必需名称摘要保持；完整包测试源91→去连续标签3项为88→去上一阶段4项为历史84；旧native来源196／格式28，Completion格式25。新默认hook互补闭合，实验不能从HTTP或环境启用，old+new故障双标签明确不支持。保持180秒、256次真实循环、2MiB、原publisher／validator及全部历史失败；未改生产、main或Registry。

最新回归核对（2026-10-26）：开发提交`3c6d45633afcf92923340d7dbc04bddb6e9e526b`已推送。ordinary 687／688通过，唯一新增对照MODEL漏RecoveryOwner前置；normal race 586通过／1失败／1运行时超时／100未启动，包180.047秒；独立full诊断687通过／1失败，147.671秒且未超时。原件与root计数复算均已封存，正在只修MODEL前置；不改产品validator，不把单项70.24秒通过当完整回归通过。旧S2与首次Completion新CI状态成功，尚未重做新提交全9 ZIP原件验收。下方9ad记录保留为已接受的限定基线；连续HTTPS候选仍待集成及真实Linux运行，整套系统与生产仍未完成。

最近核对源码：`9adbbe0419668884db9b75391b3cbead2e1aa9b6`（2026-10-26，Asia/Shanghai）；ordinary 688／688通过，race 584通过／1运行时超时／103未启动，180秒累计预算仍未关闭。首次真实 Completion 四模式已有本提交9 ZIP／167成员原件验收与root复算，不再仅依赖4bbbe旧接受。后续仍需产品恢复API、恢复后普通发布与连续恢复。随后浏览器与旧NOW条目保留为各自日期的历史记录，不表示已验收或已放弃。

**当前处于开发与隔离验收，未完成整套系统，未进入本轮生产切换。**

## 当前阶段：SYS-06 恢复完成与产品接续

| 任务 | 当前状态 | 已核实的进展 | 尚缺什么 |
| --- | --- | --- | --- |
| 固定双配置正常发布与 UNKNOWN 不重发 | 限定隔离验收通过 | 已接受 `2bba397` 的真实正常服务、响应丢失及独立复算；参见 SYS-06 文档 | 不等于全部故障、互联网业务或生产验收 |
| 持久 S2 与 Completion 模型 | `c1f9` 限定隔离验收通过 | 25 ZIP／442 成员；普通／race／full 各 1937 语义、661 必需项；旧 S2 四模式已核 | race 包距 180 秒仅余 3.633 秒；稳定余量、完整私有 WAL 证明仍缺 |
| 首次真实 Completion | 1c1fa28四模式限定隔离验收通过 | [1c独立审计](evidence/sys06-1c-first-completion-original-audit-20261026.json)：run40315108103，9 ZIP／167成员；原checker与fresh字节一致 | 不代证service rebind、产品API、普通发布、第二恢复或完整私有WAL |
| 当前提交其他三套 CI | 505 normal及diag single/full原件接受 | [505原件](evidence/sys06-505-normal-diag-audit-20261026.json)：ordinary/race各1992 semantic，full 688/688、0fail/skip/unfinished；包128.994秒 | 只接受本次样本，不证明稳定性能、业务API或生产 |
| 失败恢复协调器与产品 API | 1c1fa28限定隔离验收通过 | [两MODEL和31 HTTPS原件](evidence/sys06-1c-continuous-original-audit-20261026.json)及[root复算](evidence/sys06-1c-root-original-replay-20261026.json)接受；原verification与fresh字节相等；同HEAD旧S2和首次Completion另有独立原件接受 | 不代证完整故障矩阵、私有WAL、公网业务或生产；下一源码仍须重新绑定并验收 |
| 恢复后普通发布与第二次恢复 | 1c1fa28连续31链限定隔离验收通过 | 实际UNKNOWN→恢复→普通ACK→第二UNKNOWN→第二恢复，Go、原checker与fresh均通过 | 清理调用最终核心归属的P1增强仍待集成及运行；完整故障、容量余量与生产仍缺 |
| 连续恢复后的清理调用归属 | 独立源码候选／CPU通过，尚未集成或运行Go | 外部cleanup-core v2在1463源完整overlay上6项MODEL通过；旧稀疏overlay缺fixture失败记录保留 | 验证最终第二恢复核心的清理归属与源码保证的偏序；不得把首恢复RecoveredCore误当最终核心；需独审、Go及真实Linux证据 |
| 整套系统、灰度及生产读回 | 未完成／本轮未执行 | SYS-01–30 原范围保留 | DNS、多内核、业务分流、企业治理、UI、容量／浸泡、备份回滚、授权灰度及生产读回 |

详见 [SYS-06 实施与逐次证据](SYS06-MIHOMO-LIFECYCLE-IMPLEMENTATION.md)。新源码的 CPU 模型、Linux CI 终态、原件复算和产品／生产验收分别记录。平台9槽；root加8子代理同时running已有[实际列表证据](evidence/eight-child-concurrency-observed-20261026.json)，不是配置推断。执行子代理沿用 GPT-5.6-sol / high；当前活跃数量另查实时代理列表，不能把历史峰值当当前运行数。

当前凭据输入拆分见[设计与启动bundle约束](CONTINUOUS-BOUND-CREDENTIALS-DESIGN.md)，状态为冻结源码候选／待集成HEAD运行验收；旧全scalar协议冲突已用[纯源码样例](evidence/sys06-6e309-public-schema-conflict-reproducer-20261026.json)实际复现双fence拒绝，未读取任何实际私值。

## 历史阶段：2026-10-24 能力页真实浏览器验收

以下保留当时状态；该浏览器范围尚不能由后续 SYS-06 内核验收代证。78 实际 CI 旧订阅任务成功、新能力任务失败，时间假设修正后的真实复测仍以其专门证据为准。

这里只勾选已经取得证据的交付；代码完成、CPU检查和真实浏览器通过分别记录。下面状态优先于随后保留的历史段落。

| 任务 | 当前状态 | 已核实的进展 | 尚缺什么 |
| --- | --- | --- | --- |
| 统一验收合同 | 已形成／待整体验收 | 17份公开证据合同已落盘，两种配置、两种浏览器、默认关闭写门 | 联合验证合同与全部实现一致 |
| 共享收集与进程监管 | Linux辅助门通过／新场景运行未通过 | b2新173辅助项在实际Linux CI通过；旧订阅8个producer成功；新能力4个producer在UI_RUN失败 | 排查四份失败原件，再验新场景完整进程与清理证据 |
| 浏览器驱动与页面采集 | 时间假设修正188项辅助检查通过／真实复测待验 | 78实际v2首拒绝为DOCUMENT TIME；官方源核对后保旧85 Node＋新增1合法时序例；其余安全及成功门保留 | 统一提交并真实复测，不能从CPU通过推导新场景可用 |
| 独立证据检查器 | 78源码绑定通过／新原件待验 | 78两次实际源码绑定CLI退出0、187辅助转录报告相等；b2新能力4个fresh失败保留 | 真实17份成功原件及独立语义复算，CPU不代证浏览器 |
| CI接线与主代理集成 | 78部分成功／新能力仍失败 | 78父门及订阅读回成功、旧订阅16任务成功，新能力8任务失败；4份v2原件144成员已核；首失败TIME，未导出原始时间 | 核对固定Chromium实际分支，修正无依据的时间假设，再跑新源码实际CI |
| 真实浏览器与视觉验收 | 新能力场景未通过 | 四份失败原件均为UI_RUN，serverExitCode=0、controllerExitCode=1；尚无完整成功证据 | 查明原因并修复，再验桌面／移动截图与独立证据 |
| 灰度、生产读回及运营闭环 | 未执行 | 仍在隔离开发范围 | 前置验收、明确授权、备份／恢复演练、灰度与实际读回 |

- [x] 建立统一证据合同。
- [x] 完成共享收集链路及本地CPU检查。
- [x] 完成浏览器驱动及本地CPU检查。
- [x] 独立检查器本地交接与主代理CPU复核；实际浏览器证据仍待。
- [x] 448e20b CI精确门接齐、推送及源码绑定CLI复算；原真实CI失败已取得。
- [x] 修正候选完整辅助检查702项通过，包含新173项；运行时要求保留。
- [x] 修正候选统一提交、源码绑定CLI及新Linux CI运行；整体CI失败已记录。
- [ ] 实际浏览器、截图和独立证据重算验收。
- [ ] 灰度、生产及整套运营闭环。

查看方式：实时看板显示执行动态，本清单显示任务状态、证据与剩余事项。看板当前会估算对话进度，且可能未识别全部子代理；这些数值不能用作项目完成率或人员统计。本清单在取得实质结果后更新，并非每秒自动同步。

此前11:15状态：5f17544的订阅UI原件50条原CLI已完成独立复核；父门ordinary／race各2670项语义用例通过原检查器。其镜像lint及探针CDP仍失败，整体回归未通过。修正集成当时已在1d4b59d开发提交，304前端尚未确认；上方11:48结果更新该历史状态。SYS-03真实未知／超时闭环仍缺。

11:33追加进展：16原PNG已逐图审查，可见首屏正常；移动下方业务／完整回执仍缺视觉覆盖。DemoOverview把candidate硬编码为Shadow的矛盾已在918bc36纠正，新增2项声明，最新候选要求306前端／14文件，尚未实际运行。中性supervisor仅三个生命周期leaf完成抽取，205纯CPU用例通过，根新19精确事件门实际exit 0；完整能力页场景仍未实现。详见[前置与剩余接缝](P2-CAPABILITY-REAL-BROWSER-PLAN.md)。

- [实时执行动态](http://127.0.0.1:8765)：12:57已实际读到HTTP 200、connected=true及本项目当前动作，每 3 秒读取 Codex 动态；只监听本机，不改任务或生产。入口失效时可运行 `D:/Git/codex-task-monitor/start-monitor.cmd`。
- 本清单是项目状态真值：每次取得实质结果后更新状态、证据和剩余事项。不是后台每秒自动读取全部项目状态；停止工作时也不会假装任务仍在运行。
- 监控台的“估算进度”不是项目完成率；本清单不显示虚构的整体百分比或交付日期。
- [完整进度与历史记录](PROJECT-PROGRESS-LEDGER.md) · [功能基线](FUNCTIONAL-BASELINE-v1.0.md) · [本阶段证据与边界](P2-SUBSCRIPTION-FEEDBACK-REPAIR.md)。

## 状态说明

| 状态 | 含义 |
| --- | --- |
| 隔离验收通过 | 指定源码、环境和用例有实际证据；不代表全功能或生产上线 |
| 已实现／待补验 | 已有代码或部分证据，退出条件尚不齐全 |
| 未通过 | 已取得明确失败证据，不能被其他成功项抵消 |
| 待完成 | 尚有工作，或没有当前活动进程可证明仍在执行 |
| 待实施 | 设计／规划项，不能算已交付功能 |
| 待授权 | 涉及生产或外部权限，须明确范围、备份和回滚后再做 |

## 历史优先任务（2026-10-24）

| ID | 任务 | 状态 | 交付物／实际证据 | 下一退出条件／依赖 | 负责角色 |
| --- | --- | --- | --- | --- | --- |
| NOW-01 | 订阅失败、未知结果、回执提示修复 | 隔离验收通过（有限范围） | `e4156d6`；真实前端 222/222，旧197＋新25名单保留；明确拒绝后的残留等待已实际看图消除 | 真实 unknown／timeout 仍需另做浏览器场景，不以 mock 代证 | 前端＋测试 |
| NOW-02 | 创建／本地准入／远程抓取／批准负例双浏览器 | b2旧16任务及原50门有限通过／新能力8任务失败 | [指定源码验收](evidence/p2-b2b226d-old-subscription-acceptance.json)：50原CLI实际exit0／50报告同producer／34同fresh；1035源、16ZIP466成员前后稳定且根独核；新能力失败保留 | 新能力诊断候选187辅助通过，仍须真实CI与根因修复；完整B01–B23／真实unknown／timeout及视觉范围仍缺 | 测试＋主集成 |
| NOW-03 | 候选镜像、Registry与生命周期验收 | 1cde指定原件复算通过（有限范围） | [镜像40059993206](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40059993206)原前端306及Go各732、Registry各3门已核；后续六条完整产品CLI实际6／6退出0、报告同CI字节，1470原件／1013源blob前后稳定；[跟进](evidence/p2-1cdeba4-image-acceptance-followup.json) | 1356份不同投影参与语义重算，另114份仅保管校验；不代证448e20b、完整故障矩阵或生产 | 镜像／安全＋测试 |
| NOW-04 | 本机证据异常的保管恢复及总复算 | 918新D原件已独立复验／原异常原因待查 | 918订阅16 ZIP／466成员、探针2 ZIP／192成员前后bytes／CRC／SHA一致；1011源码和50／14耐久执行记录齐全。5f旧证据及C异常原件不覆盖 | 本次稳定不等于未来耐久或原异常原因已修；新增证据继续独立保管 | 主集成＋独立复核 |
| NOW-05 | 旧探针双浏览器取消请求排查与修复 | 918有限正常路径验收通过／长期稳定性待验 | [探针40058689830](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40058689830)两引擎各7原CLI共14实际exit 0、14报告同CI字节；每引擎7正常EOF／原八counter零／新旁证完整。两ZIP192成员及1011源blob前后稳定 | 历史5f缺失和1d PW原门失败保留；本次成功不证明唯一根因或长期稳定。真实缺失仍拒绝，完整能力页／公网业务和生产不在本范围 | 前端／传输＋测试 |
| NOW-06 | 父门及旧订阅后端回归 | b2 CI成功／本机复算待验 | [父40068275506](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40068275506)、[订阅40068275429](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40068275429)实际success；此前448本机原CLI因public-file-open-race退出1，未进入业务语义层 | 保留旧本机拒绝；b2原件本机重算须独立取得证据，不由CI成功推导 | 后端＋测试 |
| NOW-07 | 本阶段机器证据、失败勘误和台账归档 | 78诊断及b2验收记录已推送／新CI待核 | 78的14文件已推送；187辅助项及两次源码绑定CLI已核；b2原50门独立复算证据已归档。新CI实际限流无句柄，旧失败保留 | 新CI原件、失败原因和后续修正继续追加；生产与main未改 | 主集成 |
| NOW-08 | 任务清单与实时查看入口 | 快照预览已验；源文件直读待服务重启 | [项目看板](http://127.0.0.1:8765/#project)实际显示38任务／7阶段；解析25项通过。实际搜索DNS得4项、展开／焦点跨刷新保持、原实时页连接正常，桌面1280及移动390无横向溢出、控制台零错误／警告 | 自动重启监控进程被审批策略拒绝，运行中服务尚未加载新直读接口；页面标快照及采集时间，不冒称源文件自动刷新。主系统CI及生产未被这些看板检查代证 | 主集成 |

## 历史阶段可勾选清单（2026-10-24）

这是阶段任务，不是完整项目完成率。负责人和依赖见稳定ID；不以尚未校准的工期承诺交付日期。

- [x] NOW-08：确认本机实时看板连接和本项目当前动作。
- [x] NOW-02／04：完成5f订阅UI原件50条原CLI及保管独立复核。
- [x] NOW-06：核对5f父门普通／race各2670实际事件及原检查器。
- [x] SYS-01快照切片：918实际SnapshotTruth44／44通过；仅指该有界显示合同，不包含body字节限额、请求deadline或整个SYS-01。
- [x] NOW-03切片：1cde实际CI及306前端、Go／Registry原文本门已核；六条完整产品CLI复算通过，仅限1cde原件。
- [ ] NOW-05：918双引擎原14门及新收集正常路径已验；历史偶发失败唯一原因及长期稳定仍待，不能以一次通过结案。
- [ ] SYS-01／23：能力页、内核页真实场景已集成，b2两配置×两引擎实际失败；修复与成功验收未完成。实际证据总览另有隔离代码及36项Go／39项前端测试声明，全部未运行、未推送。
- [x] NOW-07：完成5f机器记录、失败保留和1d4b59d统一提交；新CI另行验收。
- [ ] SYS-26–30：整套恢复演练、容量／浸泡、授权灰度、生产读回和运营手册；仍未完成。

## 整套系统剩余任务

以下是功能基线的执行索引，不是宣称这些模块已经全部实现。已有底座统一标“已实现／待补验”，只有闭环完成才升级状态；实际细项和历史以链接文档为准。

| ID | 任务／交付物 | 状态 | 依赖与验收出口 | 负责角色 |
| --- | --- | --- | --- | --- |
| SYS-01 | 功能事实清单与所有页面／API／运行态逐项对账 | 1cde快照／提示切片已验；整体待补 | [能力纠正](P2-CAPABILITY-TRUTH.md)已有分层证据；1cde前端306实际通过。新能力页场景已有本地实现及CPU检查，真实浏览器与真实运行态仍缺 | 主集成＋产品 |
| SYS-02 | 后端控制面、RBAC、审计和耐久状态完整异常矩阵 | 已实现／待补验 | 既有分层基础之外，补全跨库异常、轮换、恢复、背压及资源边界 | 后端＋安全 |
| SYS-03 | 完整订阅B01–B23矩阵 | 已实现／待补验 | 真实分页、多来源、坏数据、写门、重启持久化、scope/owner拒绝和完整移动操作；依赖NOW-02／05 | 订阅＋测试 |
| SYS-04 | 1/N订阅识别、转换、去重、隔离与安全刷新编排 | 已实现／待补验 | 本地准入底座不能代替自动调度；补真实失败保留LKV、来源变更及回退 | 订阅＋后端 |
| SYS-05 | 完整配置编译、冲突／遮蔽检查、业务自定义分流 | 已实现／待补验 | 完整目标内核配置、规则顺序和DNS／出口一致性；不能以片段编译或规则静态匹配代证 | 分流＋内核 |
| SYS-06 | Mihomo真实写适配器与发布生命周期 | 正常／UNKNOWN／旧S2及首次Completion四模式限定隔离通过 | [实施记录](SYS06-MIHOMO-LIFECYCLE-IMPLEMENTATION.md)与本页最新核对为准；产品恢复API、普通epoch接续、第二恢复、完整故障矩阵及生产灰度仍缺；生产写门默认关闭 | 内核＋运维 |
| SYS-07 | sing-box实际适配器 | 待实施 | 版本协商、编译、协议兼容、真实进程、读回、回滚；不以能力矩阵代替实现 | 内核 |
| SYS-08 | Xray实际适配器 | 待实施 | 与SYS-07相同的完整生命周期及真实协议矩阵 | 内核 |
| SYS-09 | 正向代理接口与代理服务端 | 已有模型／待实施运行闭环 | 实际监听、账号／ACL、证书、限额、审计与防火墙边界，不能把表单保存当监听成功 | 网络＋安全 |
| SYS-10 | 自建节点与协议扩展机制 | 待实施／边界复核 | 真实互通、认证、密钥轮换、兼容性和安全评估；不承诺私有协议可保证规避识别 | 协议＋安全 |
| SYS-11 | DNS数据面、缓存、内部／国内／境外路径 | 待实施／补齐 | 独立版本与回滚、DNSSEC、双栈、上游故障恢复；既有其他DNS服务不算新系统完成 | DNS＋网络 |
| SYS-12 | DNS泄漏、绕过及解析／流量出口一致性 | 待实施 | 终端→网关→DNS→出口实际测量，保内部权威域与管理恢复路径；依赖SYS-11 | DNS＋测试 |
| SYS-13 | 节点能力、业务可用性与稳定性评估 | 已有探针底座／待补齐 | 延迟、丢包、抖动、TLS／HTTP、出口身份、真实业务、TTL／置信度和历史结果 | 探针＋评估 |
| SYS-14 | 专用池、空池、固定出口与防抖切换 | 待实施／补齐 | 依据SYS-13能力证据；支付／交易固定出口，过期或冲突证据不得盲切 | 策略＋评估 |
| SYS-15 | 反向代理与API网关 | 待实施 | 实际TLS/mTLS、证书轮换、路由、限流、熔断、灰度及审计 | 网关＋安全 |
| SYS-16 | 隧道与零信任 | 待实施 | 身份、设备姿态、应用授权、重叠网段、路由泄漏、故障恢复实际验收 | 隧道＋安全 |
| SYS-17 | 多节点／站点管理与SSH部署 | 待实施／补齐 | 受信主机身份、最小权限、幂等安装、受限执行、版本读回及独立恢复，不存明文凭据 | 运维＋安全 |
| SYS-18 | 自主诊断与受控自动修复 | 待实施 | 事件状态机→计划→预算→执行→独立验证→回滚；保冷却、抑制、人工冻结和不可达恢复 | 自动化 |
| SYS-19 | AI建议、学习与受控执行 | 待实施 | 数据脱敏、来源证据、能力边界、提示注入防护、审计、审批；不能以AI判断替代业务证据 | AI＋安全 |
| SYS-20 | 企业身份、多租户、组织与委派治理 | 已有本地权限底座／待补齐 | IdP／SSO／MFA、会话／撤销、租户数据与密钥隔离、配额和紧急访问 | 企业治理＋安全 |
| SYS-21 | 操作记录中心、统一遥测和证据导出 | 已有底座／待补齐 | 谁／为何／做什么／实际状态／验证／回滚均可追溯；脱敏、独立验签与集中保管 | 审计＋可观测 |
| SYS-22 | 告警去重、抑制、升级与恢复通知 | 待实施／补齐 | 真实故障与恢复事件、渠道权限、限流与审计；当前未授权微信推送 | 可观测 |
| SYS-23 | 全功能真实界面、拓扑交互与人性化操作闭环 | 已有工作台／待补齐 | 页面逐项接真实后端；拓扑hover／详情、权限、错误恢复、键盘／读屏／视口和反馈验收 | 前端＋产品 |
| SYS-24 | HA、主备、脑裂保护与独立故障域 | 待实施／环境待具备 | 单控制器不得冒称HA；独立管理路径、有状态业务和故障域实际演练 | 架构＋运维 |
| SYS-25 | 供应链、签名、撤销与正式发行 | 已有隔离验收／待补齐 | 完整轮换／故障／来源矩阵、企业密钥、依赖审查、正式Registry来源与发行流程 | 安全＋发布 |
| SYS-26 | 整套备份与恢复演练 | 待完成 | 配置、状态、身份引用、任务、证据一致恢复，实测RPO／RTO；不以局部状态重启代证 | 运维＋测试 |
| SYS-27 | 全系统性能、容量、故障和长期浸泡 | 待完成 | 整套端到端及资源背压、断网／崩溃／磁盘满／依赖异常；依赖各运行模块 | 测试＋运维 |
| SYS-28 | 小范围生产灰度 | 待授权 | 所有前置验收、明确目标、备份、回滚包、独立恢复与观察停止条件；先通知用户 | 主集成＋用户 |
| SYS-29 | 生产读回与实际业务验收 | 待授权 | 版本、配置、权限、DNS、路由、出口和真实业务逐项核对；不能由CI绿灯推导 | 运维＋用户 |
| SYS-30 | 升级、回滚、故障处置与运营手册 | 待完成 | 可执行操作、证据路径、回滚和救援演练、交接与验收签署 | 文档＋运维 |

## 更新约定

1. 先取得实际结果，再改状态；证据缺失时保留“待补验”或“待完成”。
2. 失败记录只追加后续修正，不把旧失败改写为通过。
3. “本轮对话结束”“子代理结束”“测试数增加”都不意味着项目完成。
4. 生产任务须另行明确授权、先备份、说明恢复办法，再执行与实际读回。
5. 本清单是执行索引，不缩小[原始功能基线](FUNCTIONAL-BASELINE-v1.0.md)；新增细项需保留稳定ID、父任务与验收条件。
