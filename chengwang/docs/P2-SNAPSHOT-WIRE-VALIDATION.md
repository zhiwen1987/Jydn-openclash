# SYS-01：完整快照显示解码与失败诊断集成

状态：工作树候选已实现，尚未取得本候选真实CI。基线源码为 `5f1754487507f6ec76d7b8872abf6e7cb89bdc07`。本文区分基线实际失败和本次修正；不改变生产、不合并main、不正式发布镜像。

## 为什么修正

`getSnapshot`此前将JSON直接断言为Snapshot。畸形列表、缺失DNS字段、未知来源或错误布尔值可能进入渲染；Go真实nil列表则可能被误当作格式错误。完整字段解码要依据实际Go wire，而不是为了通过不完整的旧合成样本放宽要求。

同源码镜像CI的实际260项Vitest通过，但随后ESLint因capability-report.ts里的控制字符正则失败，后续构建和镜像流程没有执行。探针的两份新被动诊断原CLI均因EXPECTED_EXTRA失败，原CDP浏览器另有failedRequests=1；这些失败必须分别保留，不能把采集修正当成产品网络故障已修。

## 本次代码

- 新增`snapshot-report.ts`，按`internal/domain/model.go`九个结构的必需／omitempty字段表解码。必需slice显式null规范化为owned空数组，缺key拒绝；optional slice保持省略，显式null拒绝，显式空数组可接纳。不把空列表解释成健康或库存完整。
- 保留`requireCapabilities`；严格区分布尔、有限数值、安全整数和显示身份。PoolStatus按(name, region)去重，界面同步使用复合React key并显示区域；这不是真正跨时间稳定poolId。
- 保留真实RFC3339Nano精度与时区，检查原始日历，避免非法日期被Date自动归一。目标Go1.23.12依据[固定官方源码](https://raw.githubusercontent.com/golang/go/go1.23.12/src/time/format_rfc3339.go)核对；未运行本机Go。
- 每次返回owned对象和列表；固定格式／传输错误文本不带输入值或cause。调用方取消在fetch、响应和body续体保持固定AbortError，不传播signal.reason。HTTP失败不读错误body。
- 这是额外有界的客户端显示接受合同，不能代替策略校验、引用校验、授权或数据面健康。未知协议、字段及超出JS安全整数范围会拒绝，未来wire演进须显式迁移。
- 原App两个DNS合成fixture及CapabilityTruth一个fixture补齐Go必需的四个DNS字段，保留原测试名称、断言和业务意义；不通过放宽decoder兼容错误样本。
- 原能力解码器的控制字符正则改为等价字符码范围判断，不关闭ESLint规则。实际lint通过仍待新CI。

## 显示限额及仍未覆盖的边界

普通行1024、事件4096、单pool成员4096、集合总元素16384；字符串UTF-16累计上限1048576。代理参数采用现有validator的显示范围。延迟／数量非负、百分比0–100等是客户端显示约束，不声称Go原始struct已经强制这些不变量；未知延迟应将来采用显式未知字段，不伪装为0。

仍使用response.json：这些限制发生在JSON解析后，**不限制网络body字节或解析前内存**；没有原始JSON重复key检查，也没有新增快照请求deadline。服务端当前仍生成demo快照；合成live防御用例不能当成真实live provider或生产验收。大规模企业库存仍需分页、稳定ID和版本合同，不能靠无限提高单页限额完成。

## 被动诊断修正

未知requestId的ExtraInfo只保留有界私有安全投影或INVALID哨兵；最多7个pending及128个已识别非status ID。只有原session、requestId、nonce／mount／request、frame、GET和无凭据检查通过后才关联。已识别普通资源的附加事件丢弃，不导出原始头、URL、IP、nonce、body或异常。重复、孤儿和超限不能悄悄变成完整，真正缺失仍触发EXPECTED_EXTRA。

不新增CDP命令、请求、重试、timer或等待，不改原八零、公开schema和旧产品检查器。早期事件是一个有证据支持的采集缺口候选；原5f原件没有到达顺序字段，不能据此确定其三个缺失事件都是早到，更不能归因原CDP failed1。

工作流保留旧20个Node名字并精确增加14个，总34；Python28名单不变，辅助门合计62。EOF检查改为显式依赖原browser、request-binding及实际browser-identity三门成功且工作流未取消；独立诊断失败不再遮住可执行的EOF证据。诊断步骤本身仍失败，不使用continue-on-error，不把整个job变绿。这是[GitHub状态检查函数](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions)的明确条件接线；真实执行仍需新CI确认。

## 验收要求

新增44个SnapshotTruth测试声明，排序fullName以LF连接、无尾LF的SHA256为`f5d8cf23ab45fb50cde16918352285d85fb020a1b68639ca57fe015268f20c4f`。前端门保留旧260个名字，下一要求为304项／13文件／零skip。**304只是候选要求，尚未运行，不是通过数。**

已实际完成的集成检查：当前workflow原heredoc使用真实34项Node TAP及28个Python start/pass事件，子进程exit 0；旧20项TAP被新Node门实际exit 1拒绝，无PASS。证据摘要`188b9a28b782f77a7a825ba5d289b835f37ce348435868d1113e981bc17b0250`。同一份5f真实260前端JSON由旧原门接受、新304门拒绝；没有构造304成功转录。App旧10、CapabilityTruth旧20及新Snapshot44名称核对通过。

根独立解析40份TS／TSX文件无AST语法诊断，17个workflow Bash块及offline gate通过Bash语法检查。AST里的268个literal声明未展开旧参数化用例，不能与运行时304项混称；初始本地AST包装器错误地等同两种计数，失败日志已保留，修正的只是包装器，不是产品或验收门。根静态记录摘要`ec6ddd8176b33b58f563570b31015ff84e3c580bde333900053a636446dbebe7`；用户三个原scripts脏改前后hash不变。Bash块语法不是完整Actions执行或YAML语义证明。

5f实际分层结果另存[机器记录](evidence/p2-5f17544-partial-ci.json)，整体明确为NOT_PASSED，保留lint、原CDP网络失败及不完整诊断。

本地仅做AST、Go字段合同、纯CPU辅助检查及原转录门复核；不运行Go、Vitest、tsc、ESLint、Vite、Docker、业务服务器或真实浏览器。最终必须取得新源码attempt 1实际CI和原件，确认类型、304前端、lint、构建、完整旧回归、双引擎正常TLS及进程退出。能力页／内核页独立真实浏览器场景仅有实施卡，尚未实现，不能由订阅UI成功代替。

整套系统备份恢复、实际多内核写入、DNS数据面、自动编排、完整订阅矩阵、容量浸泡、授权灰度及生产读回仍见[LIVE-TASKS](LIVE-TASKS.md)，不缩小原功能基线。
