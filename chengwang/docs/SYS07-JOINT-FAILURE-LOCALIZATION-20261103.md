# 联合场景失败：安全定位边界

已验收的提交74730eb中，P207 Go与原31步隔离HTTPS链通过；joint run41484652782的CPU摘要亦为47项Python与Go PASS，但实际场景SCENE_FAILED，独立场景校验与fresh replay未运行。失败原件没有阶段字段，不能根据七秒耗时、私有文件数量、大小或摘要推断B0/J1/R2进度。

[只读定位设计](evidence/sys07-joint-failure-localization-design-20261103.json)确认：嵌套privateDiagnostics的生成点表明namespace EXIT trap曾运行，但仍不足以定位isolation、prepare、fixture、B0、J1、R2或后续清理/私有检查中的失败。静态目录权限没有显示必然错误，权限不是已确认根因。

实现候选仅修改CI harness：固定九个操作阶段及UNKNOWN，包含workflow的pre-unshare入口、namespace setup、isolation、runner prepare、fixture、B0/J1/R2、runner finalize和私有sanitizer的完整边界；精确集合由代码与测试冻结。source-commit绑定的canonical固定名私有记录必须经过有界、单调、regular-file/no-symlink和关闭枚举检查，才可投影到失败摘要。

允许诊断仅限阶段/上次完成阶段、静态Failure.code、白名单异常类别、共享静态capture-name及上次完成capture-name。禁止异常消息、原始类名、路径、URL、HTTP状态/响应、body、令牌、私有日志或变量值。缺失、未知或不可信的记录不产生成功断言；原失败保持非零。阶段诊断本身不构成业务验收。

rev2-final候选已冻结、通过独立SOURCE_ACCEPT_FOR_INTEGRATION_AND_EXACT_CI并由root集成十个路径。旧v1因缺少named-path读回和短读循环保留为未接受；pretest freeze亦不作接受输入。最终补充短读成功和named-path替换拒绝负测，所有失败继续非零，P207 workflow/contract字节不变。

- [最终来源manifest](evidence/sys07-joint-diagnostics-rev2-manifest-20261103.json)
- [源码收据](evidence/sys07-joint-diagnostics-rev2-source-receipt-20261103.json)
- [独立审查](evidence/sys07-joint-diagnostics-rev2-independent-review-20261103.json)
- [集成后来源检查](evidence/sys07-joint-diagnostics-root-source-20261103.json)
- [实际63/58模型核验](evidence/sys07-joint-diagnostics-root-models-20261103.json)

root实际运行63来源模型及58场景合成模型，producer退出0，child units为58且与冻结收据字节相同。首次root汇总模板遗留jointModels=47；该汇总被拒绝并保留，随后根据AST测试名、原始日志完整58项与child JSON独立复演，生成上述正确核验收据，没有重跑或覆盖原结果。来源检查保持491项Go执行要求，joint闭包保持841。尚未执行本次Linux场景，定位代码不构成业务根因修复。

另有[五lane审计](evidence/sys07-747-other-five-lane-summary-20261103.json)和[容量/基础回归诊断](evidence/sys07-747-capacity-foundation-diagnosis-20261103.json)：P207的通过不适用于不同测试范围。容量609/1/79为180秒Go timeout后的最终分区，120秒仅停止CPU profile；基础回归亦拒绝，动态首条谓词未知。未证明死锁、CPU不足或性能修复，未加预算、删测试或自动重跑。

生产环境未改。此记录是诊断改进计划，不声称已知本次场景根因、已完成修复或已上线。
