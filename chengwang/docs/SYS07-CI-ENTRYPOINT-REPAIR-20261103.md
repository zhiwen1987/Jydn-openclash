# SYS07：Go guard 分类、采集入口与转换计数修复

代码提交 `120b2dff64006f2013da03d991732e78c130b475`，代码树 `d1a4f24b04c5a95fc815f0e0640183f188b92e15`。本批八路径已备份、完成组件独审和两个组合切片复核，由根会话手动集成并确认树完全一致；不是上线记录。

## 真实失败与源码修复

- fcdb P207 run41520039871/attempt1 的有界原件显示：格式补丁为空，failure reader 正常输出，528 项中 527 通过、1 失败。唯一失败顶层为 `evidence::TestArchiveExistingCallerPolicyRejectsReceiverAndHandleEscape`；原件不含具体子测试身份。源码独立推演发现 named-result 负例的专用拒绝信息被通用 fresh-object 拒绝先截断。本批只交换两个拒绝检查顺序，不删除条件、用例或改变接受集合。[固定版本 Go parser 源码](https://github.com/golang/go/blob/go1.23.12/src/go/parser/resolver.go)支持重声明复用既存对象的判断。是否完全解决该运行失败，须由新提交 Go 验证。
- Foundation collector 的旧真实调用为 `spawn --lane ... -- child`，但 positional `REMAINDER` 把控制参数一并吞入，实际 main 桩复现退出 2、run_spawn 调用零次。现在按首个独立 `--` 拆分控制头和命令尾，头严格解析并拒绝重复、未知、缺失参数；尾部逐 token 保留，包括内部的 `--`。不改变 OwnerGuard、命令执行、信号或发布主体。
- fcdb capacity 的独立有界时间线为 `TRANSITION_CAP`；它只证明最后可信前缀，不证明 open 项导致失败。源码确认 output 自环错误消耗转换预算。本批只在真实状态改变时计数，常量 MAX_TRANSITIONS=4096、MAX_EVENTS=65536、全部 FSM/JSON/动态事件校验和 Go/profile 预算保持不变。第 4097 次真实转换仍在写入新状态前拒绝。不声称因此解决 Go timeout。

## 严格源码验收

CLI 原 38 个方法保留，新增 6 个真实入口方法；cap 原方法名保留并新增 1 个方法，共 45。工作流必须使用 Class.method 的 qualified 摘要，不能把 bare-method 摘要当作 pin。实际完整 heredoc 对新 45 日志通过，对旧 44/38 日志均拒绝，689 个 Go declaration 身份不变。

根会话在干净的 120b2 上重新运行 211 项受影响 Python 方法：P207 83、joint 83、timeline 45，全部通过，结构化 loaded/started/success 与 AST 一致，无失败或跳过。前后源码及 HEAD/tree 不变。没有本地 Go 执行。

实际 source CLI 为 842 module、21 fixture、545 source tops、528 required tops、38 changed-Go、S92/Q80、foundation 689。Joint validator 通过；853 条契约从当前提交重新生成，与跟踪文件及 pin 逐字节相同，SHA256 为 `a622b2be7e43f66dec2fbff0a01cc0b4887b3b785f711e5437106a28a62ac758`。

## 未完成与证据

最新提交自己的 Linux Go、格式/official selection/fresh、修复后的真实 collector 调用、B0/J1/R2、完整 foundation/capacity 和 31 步 HTTPS 验收仍待。旧 385ba 的 31 链通过不可迁移为新提交通过；fcdb 的 partial timeline 不能用作性能根因。完整系统、actualfs 耐久和正式上线仍未完成。

[本批证据索引](evidence/sys07-ci-entrypoint-repair-source-20261103.json)。八文件前像在 `D:/CodexData/workspace/chengwang-fcdb-root-preintegration-backup-20261103-cd03-v1`；所有旧失败、错误摘要尝试和 source-only 限制保留。生产/main/Registry/旁路由/DNS 未改。
