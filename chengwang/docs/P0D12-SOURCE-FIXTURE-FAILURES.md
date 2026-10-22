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

## 7e6d405：安全诊断确认自身模块未导入，未通过

代码7e6d40565abc948a59f945fffec64d6871c1843a，绑定39871183460/job120145729698，attempt1 completed/failure。该轮保留原启动路径，只增加闭集诊断和同一Shape方法内的诊断正反例，未放宽权限或跳过native。

- 原API日志72,429B，SHA256 `055710c85bf847ef9d5fe4aafb1bf15133f97e0274ce690bd494c195b3200bdc`；工件12466207741/27文件，ZIP257,899B，SHA256 `3a5cc20e91b8dde77ac47d7a24a805e9dd3aec1c61295c7b54ded7961476d4d7`，多份独立下载/API digest一致。
- 实际24项/0.451s，8Shape通过、16Linux失败、0skip；所有16项均为`BOOTSTRAP_MODULE_NOT_FOUND_SOURCE exitCode=1`。这确证`import fixture_source`阶段ModuleNotFoundError且name精确为fixture_source，尚不能断言具体目录EACCES/errno，也没有进入source.main/TLS/wire能力。
- 新observations/checker-tests/preflight仍未产生，失败日志被准确head检查器拒绝；后续Go/Registry/镜像门未运行，不能算回归通过。旧fixture前置通过与新privateTreeRemoved=true/testExitCode1分别保留。
- 父39871183672/job120145730690独立success，原日志5,447,444B/SHA256 `6f8cc499c930b2f39bda7f9dd0a84bab39c5fab1acf2d7f8e40e0386f19d3bf1`；普通/race各2320具名run/pass、0Test skip/fail。父成功仍不覆盖子失败。

据此下一修复移除“降权进程必须遍历checkout并按路径import”这项新前提：由可信root测试orchestrator从原只读Git绑定文件读两个原始模块bytes，通过有界`-I -B -c`在低权进程注册固定内存模块后执行；不用可写helper源码副本、PYTHONPATH，不改目录权限、UID/cap0/NNP或产品逻辑。该修复仍须下一真实CI证明，不能将实施意图当旧轮通过。

## 后续57fd54c独立验收，不改写以上失败

57fd54c的新实际Linux24项/0skip及独立观测重放通过，见[最终前置验收及剩余项](P0D12-SOURCE-FIXTURE-ACCEPTANCE.md)。这是后续代码的新结论，不把3573取消、5d/7e失败改成成功，也不据此补造旧stderr或推断旧errno。
