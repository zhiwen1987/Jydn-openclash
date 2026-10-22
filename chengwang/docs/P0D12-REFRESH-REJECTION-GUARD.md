# D12 自动刷新重复拒绝保护（本子门已隔离验收）

代码ed756d74719891c2fc473b90867dbfda95f37f0c已通过实际Linux ordinary/race各728项、父各2320项及原全部镜像回归；主代理与独立代理下载工件重算一致。[实际验收与未完成项](P0D12-REFRESH-REJECTION-ACCEPTANCE.md)。本结论只覆盖本子门，以下完整来源矩阵仍待实施，不是生产上线。

完整目标仍是企业系统闭环，生产禁动；本工作修复来源矩阵核对时发现的实际产品缺口，不取代尚未完成的来源/追代/TLS/撤销竞态矩阵。root唯一集成/提交/推送。旧全部镜像门、700个原普通/race测试及父2320测试保留。

## 缺口与选择

修复前ApplyRefresh每次调用Update，坏签/过期候选虽不推进目录，仍生成新random operation，完整拒绝使sequence+4/journal+1/audit+2。Run持续重试，重复同一坏来源可耗尽MaxOperations4096。oneShot测试源不能当产品保护。

本轮仅在trusted自动ApplyRefresh引入固定16槽、每Service进程内的拒绝工作集，无原candidate、凭据或无界map。key为本Service固定store/anchor/scope下的当前generation+catalogueSHA+candidate原bytes SHA；base变化清空，new Service/重启不继承。不同坏bytes超过工作集容量仍可增长journal，不能宣称完整抗DoS、跨重启去重或无限容量。

首次坏候选仍走原Update与真实REJECTED审计/ACK。仅当确定CodeInvalid、完整结果路径返回、且前后base不变时记忆拒绝；cancel、busy、audit/IO/poison/不确定状态不记忆。普通管理员Update完全不改，每次仍保留原审计语义。

命中不是跳过验证：新Store.PreviewUpdate用实际当前库/anchor/签名与当前真实有效时间重新执行trustcatalog.Advance，只读db.View，不put/改变logical record，不把返回值当批准或消费能力。可沿现clock保护推进内存high-water；时钟/上下文/完整性异常不能变成普通候选拒绝。Preview返回固定BaseGeneration/BaseSHA256/Eligible；真正安装仍必须再次走原UpdateTracked事务，Preview不是写入授权。

命中且重新验证仍不合格、base精确相同时，返回非nil CodeInvalid/StateMayHaveChanged=false，不生成重复outbox。不调用ConfirmRefresh、不刷新LastSuccess/Until、不把此前Fresh即时清除；原确认只能自然过期。未来NotBefore转为有效、合法候选或base变化时不能被旧缓存阻止。单实例Apply用TryLock无等待队列，其他并发尝试返回Busy。

## 分工与本轮证据

- root：Store.PreviewUpdate及8个新Linux顶层测试、协议/验收与集成，不本机Go build/test/mod。
- A：product.Service/refresh.go运行实现及16个新Linux顶层测试，不改旧测试语义，不改普通Update或HTTP DTO，不暴露fault配置。
- B：精确28项新增测试门与Python反例测试，原700集合按既有原hash逐项保留；未知prefix、漏项、重命名、包替换和额外Test都失败，不宽泛排除D12前缀。
- C：4个新真实runtime集成测试（非镜像/独立OS进程证明）在正常TLS源和API下持续坏candidate、时间转有效、来源更换/实际追代与停止join；不构造backend提前确认，不将同进程runtime结果冒充Docker镜像、独立命令进程或生产。旧D7命令测试与所有镜像门保留。

新增顶层测试数量固定为Store8/product16/command4，共28，没有新子测试，完整ordinary/race集合应为728并完整保留原700。测试fake clock仅用于单元对象，不改宿主或Windows时间、不放宽生产时间检查；runtime future-NotBefore集成使用真实等待。

本子门已完成实际Linux ordinary/race/vet、新旧完整具名集合、原全部产品镜像门重新执行和独立工件/源码重算；命令进程/同进程runtime集成与Docker镜像证明仍分别标注。完整新来源负矩阵仍另门实施，尤其现fixture_feed仅200/503，不能宣称已测错误TLS、真实403/redirect/错误帧。

## 后续矩阵不丢弃

来源Fetch拒绝（CA/SAN/SPKI、HTTP/帧、hint、rollback/fork/gap/预算/取消）、真实Apply拒绝重复、G1→G4顺序追代及合法前缀后坏候选、精确no-op/陈旧恢复/重启冷确认、真实内核屏障在途撤销分别验证。Fetch整批取回失败不返回部分batch；Apply逐代不是整体事务，不能宣称失败会回滚合法前缀。新增adversarial feed需独立安全HTTP/transport事件与有界原bytes；不以HTTP日志为空证明TLS尝试或拒绝原因。
