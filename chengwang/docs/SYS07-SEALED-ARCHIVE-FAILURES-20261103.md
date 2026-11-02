# 归档测试失败：修复与未完成边界

最近一次真实 P207 run41479327943，提交c64872682817c39fbf8c78704a3cc8df68a3b7a3，结果为489通过、2失败、0未启动，格式通过，fresh跳过。以下结论来自实际源码和规范静态核对，不冒充未公开的动态断言消息。

## PrimitiveAndNameBoundaries

nextToken 在超过1048576 token时返回 ArchiveLimit，数组结束等调用点却将其重新归类为 ArchiveInvalid。确切的one-over边界因此与规范要求矛盾。修复将底层JSON解析错误先封为ArchiveInvalid，再由value-first、object-key、object-close、array-close四处传播已经分类的错误。token、depth、string及对象上限均不改变。

原边界断言保留，补入其余三个传播点的预算负例，顶层测试数量与skip不变。此源码候选已独立接受并集成开发工作区，但尚未完成本次Go/gofmt/Linux验证。

- [静态诊断](evidence/sys07-primitive-static-diagnosis-20261103.json)
- [作者源码收据](evidence/sys07-primitive-author-source-receipt-20261103.json)
- [独立源码审查](evidence/sys07-primitive-independent-source-review-20261103.json)

## AllControlStatesAndCheckpoint

三个仅修改genesis OriginalV1 length/SHA的负例，在与未改intent-core比较时先返回ArchiveConflict，无法到达后续严格重建字节校验。将这三处期待修为Conflict可以保留篡改检测，但不足以覆盖严格字节校验分支。

独立复核要求保留原三个genesis-only负例，再新增测试专用的真实认证链构造：同步intent、migration/epoch、candidate和genesis身份并重新签名，使坏身份穿过链接校验，由实际validateSealedArchiveV8Plan在严格字节重建阶段返回ArchiveReconstructionFailed。不调整产品验证顺序，不抽取仅为测试而存在的产品比较helper，也不删除原有负例。v2 扩展候选已获 SOURCE_ACCEPT_STATIC_UNCOMPILED 并集成；尚未运行Go。

- [静态诊断](evidence/sys07-all-control-static-diagnosis-20261103.json)
- [独立诊断与修复方案裁决](evidence/sys07-all-control-diagnosis-peer-20261103.json)
- [v2 作者源码收据](evidence/sys07-all-control-v2-source-receipt-20261103.json)
- [v2 独立源码审查](evidence/sys07-all-control-v2-independent-review-20261103.json)

## 合并冻结

两个候选已叠加到开发基线 e2829f8b81ea4c31839791983e7893ddb80d4820。[最终源码冻结](evidence/sys07-combined-go-repair-freeze-20261103.json)仅包含 test.go 与 wire.go，按 UTF-8 内存重放两个不重叠补丁后与实际文件字节一致，LF。测试文件SHA为8c3925d9895f076d398b56a4bcc716d493b5b8e6d9e01cbd33368b663aeaa1cc，wire SHA为2692d55e5ab4338c1536d2733d8546f11fd0d69cce770b3e70184fa56cc04407。冻结状态仅为源码，不证明编译、格式或Go测试通过。

[合并结果独立审查](evidence/sys07-combined-go-repair-independent-review-20261103.json)已获SOURCE_ACCEPT_FOR_GO_VALIDATION：测试文件为两个已审补丁的零重叠精确并集，wire与已审版本逐字节相同；测试名集合、顶层10项及skip0均不变，静态496/491不变。仍须执行Go验证，不属于自动合并、运行验收或上线许可。

合并两个已审候选后，须按最终两份Go源码重新计算来源校验，再运行正式来源/模型检查和隔离Linux CI。当前不代表两项真实测试已通过，亦不代表A0、A1、项目或生产验收。生产环境未改。

## 辅助校验工具拒绝记录

e282 metadata工具v2的7项合成测试通过，但独立审查为TOOL_SOURCE_REVISE，尚未运行实际生成。[拒绝证据](evidence/sys07-e282-metadata-tool-v2-rejected-20261103.json)确认三个问题：rename后fsync失败时输出已可见却错误声称pending保留；输入receipt/afterimages未反向排除repo/common/worktree；Git读取未禁用replace refs。须保留v2并在新版本修正、补故障注入后重审。不能把工具测试通过或Go源码静态审通过当作校验生成完成。

## 实际校验生成与本地门

v3 修复上述三项，10项实际故障回归通过，[独立工具审查](evidence/sys07-e282-metadata-tool-v3-peer-20261103.json)接受后，由root执行实际生成。[生成收据](evidence/sys07-e282-metadata-generated-20261103.json)精确四个metadata输出，fixture校验值保持不变，joint841仅两Go来源行更新。

[实际输出独审](evidence/sys07-e282-metadata-output-peer-20261103.json)获SOURCE_GATE_ACCEPT：正式P207与joint检查器退出0，全部1693个原始Git blob核对仅预期六个来源差异；foundation保持689/688，7CTL诊断范围不变。两Go与四metadata已集成。

集成后root[正式来源检查](evidence/sys07-go-repair-root-source-20261103.json)通过，执行要求仍491；joint source_contract亦通过841/841。[本地模型收据](evidence/sys07-go-repair-root-models-20261103.json)为63/63来源模型、47/47场景合成模型，producer实际退出0，日志与测试名核验通过。没有运行Windows Go/gofmt或真实网络业务。

必须以提交后的同HEAD隔离Linux CI重新验收格式、Go、fresh和真实场景，再判断两项动态失败是否修复。当前仅本地开发门完成，不是Go通过、A0完成、生产发布或企业系统完成。
