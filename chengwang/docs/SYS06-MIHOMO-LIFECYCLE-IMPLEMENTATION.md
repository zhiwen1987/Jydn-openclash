# SYS-06：Mihomo 发布闭环的实现进度

当前是独立开发分支：04e的S1 607结构测试底座已通过正常及完整诊断、独立原件复核，旧ead格式失败保持原判；实际native启动入库、运行时关闭交接、S2、产品恢复接口及完整闭环仍未完成，尚未部署到设备。完整目标仍是：完整工件 → 私有备份 → 范围批准 → 隔离灰度 → 实际重载 → 新鲜读回与数据面验证 → 失败回滚 → 重启恢复及审计。仅有 PUT、204、配置生成或测试通过，都不能把 SYS-06 标为完成。

## 本次已有代码

### 2026-10-25 CI触发覆盖修复：固定开发分支每次提交均运行两套验收

2b63a001f14b6cc72ddb8019cd77c2b373aa5e2f只修改新adapter测试的实际formatter空白，GitHub API仅出现正常40170650512，诊断未被触发。实际旧diagnostic paths只列lifecycle／lab_recovery_plan／bootstrap_state等，未覆盖已经纳入full suite的其他Go源；正常paths也遗漏六包中的authz。此为源码及实际触发记录支持的CI覆盖缺口，不能编造该提交的诊断运行或复用d041为新提交接受。

两workflow的push均保唯一codex/chengwang-mihomo-lifecycle-20261024分支，移除paths筛选，让该独立开发分支每次提交都纳入正常与诊断验收。workflow_dispatch、permissions、concurrency、13/5 job全部执行内容、命令、固定工具链/镜像、隔离namespace、180秒/256历史/2MiB不变；不扩大main或生产写权限。改动会增加仅改文档时的开发CI开销，避免新目录或路径遗漏继续让同提交的完整验收缺席。行为依据[GitHub workflow path/branch filters](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushpull_requestpull_request_targetpathspaths-ignore)。新触发范围仍须YAML/分支约束及实际GitHub新提交运行验证，不能用源码检查当已触发。

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
