# 新建刷新库的空账本复制缺陷（源码证据）

基线：`31ac3c9c895c2c665ae6472a02a1dcb22b4ad002`。本记录来自源码阅读，未在本机运行 Go。

`chengwang/internal/subscription/refresh.go` 的 `OpenRefreshStore` 创建有效状态时令 `Ledgers` 为非 nil 空切片。`cloneRefreshSnapshot` 第208行使用 `append([]RefreshLedger(nil), in.Ledgers...)`：输入长度为零时返回 nil，因此丢失非 nil 空切片形态。`Reconcile` 在写入任何绑定前调用 `observe`；该函数克隆状态后调用 `persist`，后者再次克隆并调用 `refreshEncode`。`validateRefreshSnapshot` 第575行明确拒绝 `st.Ledgers == nil`。因此从有效新库进入首次 Reconcile 的这条源码路径必然被自身校验拒绝，尚未执行新增绑定。

运行证据另有边界：[run40533880771最终原件收据](sys06-31ac-p207-bounded-failure-original-audit-20261027.json)记录总416项通过，其中 subscription 包101项通过／19项失败，其余五包共315项通过；subscriptionctl46项未开始。最终收据哈希已由root核对并归档，运行器内重投影检查exit0不等于本机拿到原始事件重新投影；raw未公开。未公开具体断言输出或源码行。上述源码矛盾不能冒充已直接观测到每个失败top的首失败行，也不证明这是唯一缺陷。早期进度误把总416说成其他包通过数，本条与最终收据为纠正。

修复约束：复制必须保留 nil 与非 nil 空切片的区别，非空切片仍必须脱离原底层存储。不得把无效 nil 输入正常化后绕过严格校验，不得放宽 validator、失败保留或持久化规则。回归应覆盖空切片形态、nil输入拒绝、非空复制隔离、新库首次协调及持久化重开；真实 Go 与官方格式验收仍须隔离 Linux CI。

已交独立子代理核查并准备外部候选；本记录不表示修复已集成、测试通过或生产上线。
