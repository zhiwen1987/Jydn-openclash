# D12 异常来源fixture失败记录

本文件保留未通过/被替代轮次，不把父CI成功、清理成功、Windows辅助或后续通过倒写成旧轮验收成功。生产环境未动。

## 3573c9d：格式修正后被替代，不计验收

代码3573c9dcdc50b7e5bdbbeab73f70ff640aa68fd2提交后，root发现新checker末尾多一个空行；随后5d269f5只删除该空行。原绑定39870450545、父39870450403被分支既有concurrency策略取消，API均completed/cancelled。不是功能通过，也不把取消当功能失败根因。

## 5d269f5：真实Linux启动失败，未通过

代码5d269f51e68dd3874a51c02470730ecea88a25ce，绑定39870528061/job120143713004，attempt1 completed/failure。

- 原API日志72,095B，SHA256 `03f815f71a4ed87b76d0dc9ecfad6c6db78f8696708c3beab1bf04a6f05bb640`。
- 工件12466400518，ZIP257,911B，SHA256 `9952a3deb5deae1b0fd9c633d16179e6c9976eabd1f6a4b479b2ed9e93e47859`，与API digest及多份独立下载一致；27个原工件文件。
- 新套件实际Ran24/1.391s，8个Shape通过、16个Linux失败，0skip；14个成功型用例未发布ready，2个预期拒绝型用例的stderr不符合固定D12_SOURCE_ERROR前缀。原helper stderr没有导出，因此不能确定具体Python异常、errno或源路径权限根因。
- 新observations/checker-tests/preflight未产生；Go728及后续Registry/镜像门未执行，本轮不得沿用上轮结果称通过。source unchanged步骤与工件保存成功不改变失败结论。
- 实际清理报告privateTreeRemoved=true、testExitCode=1、hostTmpTouched=false、parentMountNamespaceChanged=false。主代理副本位于`C:/Users/Administrator/AppData/Local/Temp/chengwang-source-5d269f5-root-21b924790cdf4098a7355814c5f2bfa0`；临时副本和14天CI工件不是长期备份承诺。
- 父39870527899/job120143844311另外success：独立代理核原日志5,447,145B，SHA256 `a06485dcc3898de26ae36e5eac32772351e73d37ba9440eb4d7de3ccc36ef8cc`，普通/race各2320具名run/pass、0Test skip/fail；不能替代本新门。

下一轮只先增加安全bootstrap诊断：固定异常类别与受控模块枚举，不输出原stderr/异常文本/traceback/私钥，不改UID/caps、只读源、期限、24测试或34观测集合，不skip失败。取得实际诊断前，不宣称源目录权限猜测已被确认或修复。
