# UID 模型与 HTTPS 读回门：源码修复与验收边界

本记录对应源码 `b817ff797f59c5d3ff99d2eaa3fd054def366138`，tree `cd2c2ca2a52598666c5bed3f7aaa543a03c81ea5`。没有生产操作，没有合并产品 main，没有 Registry 发布，也没有本地运行 Go、浏览器、服务或容器。

## 已确认的失败证据

- exact 124a joint run 41535006908 / attempt 1 的独立安全模型原件，经当前来源校验器验证：90 个模型，85 PASS、4 ERROR、1 FAIL，无跳过；五个非 PASS 全为 UID probe 测试。原件不含 traceback，因此不能证明唯一首错。
- 独立源码审查确认测试中的 root 身份与 chown no-op 没有改变真实 Linux inode owner；清理代码直接读取 owner。旧清理 wrapper 也没有恢复只读父目录的写权限。这是强源码相关性，实际 Linux 修复效果仍待新提交 CI。
- exact 124a schema-v2 时间线：普通 Foundation 689/689、exit 0；Foundation Race 为 638 PASS、1 open、50 未开始；Capacity 为 621 PASS、1 open、67 未开始。后两者均有固定 timeout/panic 文本观察，exit 1，不能把 open 测试或文字观察当成因果定位。
- exact 124a Continuous 31 run 41535006672 被取消；API metadata 不提供取消原因。source-models 所有步骤 success 仍不等于 job 成功。API producer skipped 后，旧 fresh 条件仍尝试下载不存在的原件，造成下游失败。

## 已整合的修改

1. `54102959fcdd2243c1ee4fcb488c47ff90c7ceb7` / tree `c59a8591c76cf64a3a66f8c8001bb0e25e2cf53f`：仅测试 fixture 增加精确 probe 子树的合成 owner 视图，以及限定子树的清理权限模拟。真实 probe owner、mode、symlink、hardlink、allowlist、故障传播和最终缺席检查未修改。853 路径合同仅重算该测试行，workflow 仅更新合同 SHA pin；90 项模型名称不变。
2. `b817ff797f59c5d3ff99d2eaa3fd054def366138`：Continuous fresh job 保留原条件，再要求 API producer 的结果为 success。增加来源绑定回归；producer 失败、取消、跳过均不能触发缺失原件下载。不把它宣称为取消根因修复。

## 实际完成的源码验收

- UID 单文件及三路径组合分别独立审查。额外把底层 inode owner 模拟为 1001，八组关键测试通过；外部 sentinel、runner 和产品目录不被 wrapper 改写。
- root 在精确 54102959 干净树运行 83 P207 + 90 joint + 46 timeline + 5 profile：224 PASS。记录位于 `chengwang-5410-uid-root-models-20261103-cd03-v1/SUMMARY.json`。
- HTTPS 两路径组件独立审查，root 在精确 b817ff79 运行七项模型：7 PASS。记录位于 `chengwang-b817-continuous31-root-models-20261103-cd03-v1/result.json`。
- 224 和 7 是两个不同精确源码截点的执行，不拼称一次全回归。测试通过不代表部署或上线。

## 退回与未完成

性能组件 A v1 虽保留边界语义，却引入重复编码和多余第二轮搜索，独立审查为 REVISE，未应用。所谓 4096 次是旧循环的失败上界，尚不能宣称实际执行了 4096 次；不能据此宣称加速。约 78/80 秒的 256 历史填充测试是真实主要耗时，但替换其准备路径需要逐字段等价、seal/decode/reopen、owner 重新取得等证明，目前仅有设计。

仍需：最终提交 Linux 90 模型与真实 UID microprobe、完整 Go/格式/官方选择及 fresh 原件、联合场景 B0/J1/R2、完整 31 HTTPS 链、Race/Capacity 超时定位及通过、取消原因核实。所有这些目前都不能标为已接受。

## 交接资料

私有 JY-CW main `b01aa1197ea24ae69ff8130e0b9ccb0c30d371c9` 仅为资料归档，非产品 main 合并。已归档至 124a，payload 全量 66888 文件 / 1236376254 字节 / 零失败；另五份控制回执不计入该 payload 数。新 fresh clone 对 184 个新增/修改文件逐字节读回通过。

远端读回 v1 的 sourceCodeHead 被自动字符串替换写错，原回执保留但该字段作废；v2 已重新 fresh clone 并绑定真实 124a，另有 CORRECTION 回执。以上不证明 b817 新阶段已经补档；该补档仍待后续执行。
