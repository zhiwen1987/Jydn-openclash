# P2：批准交接负例的下一阶段实施卡

状态：只读代码分析得出的待实施合同，尚未构造或执行此场景；以下数量、HTTP及状态是事前预期，不是已验结果。不得拿现有正向流代证。本卡不授权生产变更。

## 保持独立场景与证据来源

另建 `remote_handoff_negative`，不扩大既有33步/4命令/8外审的正向合同。新journal按case/actor/source/command精确允许预期403/409，不能全局放行错误或吞transport/CSP/console/asset异常。继续固定正常API/DoT/HTTPS、私有无默认路由wire、同Git构建/进程/审计与独立fresh验证。

先经真实UI创建A/B（各revision1），Approver依次批准A旧=good-a/P1、A新=good-b/P1、B=good-a/P1。预期setup为5命令、3批准、local audit2、external audit10；没有候选或wire。

| case及请求来源 | 事前预期 | 必须独立核的副作用 |
| --- | --- | --- |
| UI交接未知但格式合法command ID | 409 `subscription_approval_required` | 新失败命令1、prepared/result外审2；资源库存、local audit、wire不变 |
| UI来源A交接B的批准 | 同上 | 同上，来源与批准不可串联 |
| UI交接A新批准、填policyRevision2 | 同上 | 同上，不把下拉选择当批准依据 |
| UI交接已被A新批准取代的A旧批准 | 同上 | 同上，不称基于时间TTL过期 |
| UI Operator读取Approver A新command回执 | 403 `subscription_forbidden`，无result/command ID头 | 无新命令、local/external audit或wire；不能假设所有403均有denied审计 |
| API-only Operator直接POST批准 | 403 `subscription_forbidden`，无result/command ID头；健康审计时denial header为recorded | 无新命令/local audit/wire，外部denied事件1；UI仅验按钮禁用和无POST，不冒称UI自然发出此请求 |
| UI Operator A新/P1/expected1合法fetch | 200 committed，A升revision2 | 新命令1、local audit1、外审2；1quarantined候选/base2，2节点unknown；3连接/12wire事件，不自动接纳 |
| API-only A新/P1/expected1再次fetch（此时实际A2） | 409 `subscription_command_conflict` | 新失败命令1、外审2；资源库存/local audit/wire不变；UI没有任意expectedRevision编辑入口，不注入React冒称UI测试 |

进入Execute的五类失败POST应返回安全 `X-Chengwang-Command-ID`，而非成功result。每次用本人读该失败回执：GET200、state failed、对应public code、auditRecorded=true、stateMayHaveChanged=false、两外审hash有、无localAuditHash；revision为提交expectedRevision（上述为1），不能当成当前库存revision。GET不能增加业务命令、审计或wire。每次失败后按页面真实stale/刷新合同恢复，不能直接覆盖状态。

按表中顺序预期终态：A2/B1、3批准、1quarantined候选/2unknown、11命令、local audit3、external audit23（22 command事件＋1 denied）、3连接/12wire。必须逐case冻结实际API/DOM、失败回执、审计和wire前缀，不能只对总数。此终态尚未运行验证。

## 不虚构过期或竞态

当前fetchApproval不比较批准时source revision与当前revision，也没有批准时间TTL。跨revision复用应另设实际正向对照，不能据代码无比较就写成已通过；原旧lab同revision noop不是这个证明。时间TTL仍是未实现/未验事项。

真正策略材料/revision变更需正常TERM/wait0后，同库新server加载新受信fixture；不能修改磁盘文件就假设热加载。post-network CAS现有Go测试使用policy seam调用Store.Import，不能冒称浏览器或真实API已经覆盖；真实双会话竞态须另立安全构造。当前同Service对同source的claim串行性必须纳入设计。

## 已检查的源码依据

- `internal/api/subscriptions.go`：86行两种409映射，342–373行失败POST的错误envelope/安全command ID头，386–404行失败命令的只读回执。
- `internal/subscriptionctl/service.go`：367–404行接纳命令与prepared/result，501–531行批准/策略/CAS校验，691–725行owner回执规则，729–768行独立denied审计。
- `internal/subscription/control.go`：409–427行当前批准选择，448–488行批准不递增来源版本。
- `web/src/Subscriptions.tsx`：交接字段、只读回执、当前版本准备及角色禁用行为。后续实施前须按新精确Git重新核行号/合同，不以本卡替代真实接口验收。

仍须补齐B01–B23其余授权、分页、恢复、故障、长稳、完整旧回归，以及正式备份/灰度/生产读回与回滚。不能把此卡缩成整个系统的完成条件。
