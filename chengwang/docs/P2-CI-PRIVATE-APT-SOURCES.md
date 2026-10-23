# P2：CI私有官方镜像源与实际版本读回

状态：实现及49项纯CPU验收完成，尚未由新源码真实CI验收。本页不是下载已修复、产品新增业务已上线或生产变更记录。

## 范围与原故障

[c7b64c4原件](P2-CI-DEPENDENCY-ACQUISITION.md)保留两PW通过、两CDP安装240秒超时和fresh跳过，原run40018960129整体failure。低重试/15秒空闲超时已经使用，不能再次增加同样参数冒充修复。本增量调整隔离CI的首选获取路径，保留有界退出及严格失败；不是历史探针取消的根因修复。

## 实际设计

1. 仅接受Ubuntu24.04/amd64/GitHub Linux CI。原四producer的Ubuntu源均2995B、镜像清单144B，合同冻结其SHA。私有复制前重新读取安全的root-owned普通文件并核这些原指纹；模板或runner变化时拒绝，不能自动降为任意源。
2. 校验原Deb822字段、四个suite、四个component、deb类型、amd64及固定Signed-By；只替换原mirror URI到新建 `/tmp/chengwang-ci-apt-xxxxxxxx/mirrors.txt`，其余原字节保留。复制后的源逆替换应恢复原SHA；不导出原源配置全文。私有目录0755/文件0644供 `_apt`读取，不放在0700实验父目录下。
3. 私有镜像优先级为Ubuntu archive HTTPS→security HTTPS→原Azure HTTP。这是**官方HTTPS优先**，不是全程强制HTTPS。APT仍负责原Signed-By签名验证；不新增第三方源、不关闭认证或日期检查、不发布或复用新包缓存。
4. update/install均明确指定私有sourcelist和空sourceparts，不写 `/etc/apt`；命令行覆盖认证、日期及三个已审主机的HTTPS验证选项，清除该子进程的APT_CONFIG。宿主配置前后相同与**有效配置已变更**分别记录，不能混用同一false声明。
5. 在实际安装前，用同sudo/env/私有路径/安全选项的只读apt-config检查普通和apt-get专属的额外source子树；非空、超时、截断或错误均拒绝。原输出可能有私有路径，绝不导出；报告只保留命令、空输出断言、退出和耗时，是可信CI投影而非独立执行公证。
6. 新增实际 `apt-get --version` 原stdout独立toolchain日志，大小/首行版本和架构由独立检查器核对。原包/Regular/Bold读回的六行日志保持独立；不把旧参考源码版本当作当前可执行文件版本。
7. 保留update120秒、install240秒、TERM后15秒KILL、每阶段一次；不重跑失败run挑绿。后续APT内置同URI重试与镜像回退仍有总预算，不能保证所有网络条件下成功。

合同：[ci-dependencies-contract.json](../deploy/subscription-ui-browser/ci-dependencies-contract.json)版本v2；原c7/v1失败记录不修改为成功。公开report仍不含密钥、代理凭据、原订阅或完整源配置。

## 独立检查与原件条件

独立检查器不导入准备程序，固定v2合同、精确命令、安全选项、私有路径闭集、原宿主指纹、归一化SHA/长度、镜像字节摘要、额外源空断言和版本原stdout。已安装文件仍是受信CI安全投影，不冒称本机独立字体字节验证、可复现包来源或签名公证。

原产品14文件闭集、正常TLS、API/DOM/审计/截图、八类错误计数、进程正常退出、旧84/新76辅助门都不修改。成功producer预期36个公开成员，fresh预期4个；fresh同时重放新依赖和原产品完整CLI，分别与producer报告cmp。原26个辅助测试名称须保留，新反例另计，不能拿合成测试替代真实APT和四条浏览器流程。

退出条件仍是新源码的四producer和四fresh实际成功，并按原ZIP/精确Git/完整CLI独立复验；未运行、失败或缺失均不得填PASS。手机首屏截图不替代完整手机交互，既定两流程不等于完整B01–B23。

## 本机实际执行与未证明

根端提取工作流内同一段Recorded unittest代码，实际执行30项准备程序＋19项独立检查器，逐名run/pass/冻结摘要匹配、0skip，原16＋10基线名称全部保留。原49测试stdout/stderr为9832B、SHA `e8813a1ef1e653182029f2dafe7708c366a0fd348e716b55ae751e2c655f45d7`，保存在：

`C:/Users/Administrator/AppData/Local/Temp/chengwang-private-apt-root-4afd984111a84af597aa58d949c78767/workflow-frozen-unit-original.log`

另实际串联A准备程序的全模拟系统边界→C独立verify通过，四日志/私有源/版本字段和实际工作树源码字节一致；这只证明模拟接口互通，不证明真实APT、Linux权限、批准源原字节、签名来源或Git执行链。工作流10个run块通过 `bash -n`，不是执行了其中的安装或浏览器。组件顺序审查已修正：要求相同四组件且无重复，不强制原顺序，复制仍保留原字节。

尚待真实CI验证的第一道边界是该2995B源是否符合Deb822预检；不符合应保留失败原件，不自动放宽指纹或字段。其后才是实际APT版本、两额外源树空检查、`_apt`可读性、索引与下载、包/字体读回，以及四条真实产品路径与fresh。尚不能用本机49PASS预报上述项目通过。

## 已查阅的上游依据

- [runner-images固定源配置](https://github.com/actions/runner-images/blob/c03600ca998467081ccec9bb9dbf5de6b68e862a/images/ubuntu/scripts/build/configure-apt-sources.sh)：原来已有官方镜像回退，不是本轮新增了回退机制。
- [APT固定ParseCommandLine实现](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/apt-private/private-cmndline.cc)：binary专属子树移入后才解析命令行，不能用apt-config的默认binary身份代验apt-get额外源。
- [apt-config DoDump](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/cmdline/apt-config.cc)与[Configuration::Dump](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/apt-pkg/contrib/configuration.cc)：指定子树会遍历其子项，EmptyValue=false排除空值；不是简单读取根字符串。
- [方法配置查找](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/methods/aptmethod.h)与[TLS使用点](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/methods/connect.cc)：host专属设置优先于全局值，不能只检查全局true。
- [APT已有包缓存快速路径](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/apt-pkg/acquire-item.cc)：同尺寸缓存不能被宣称自动重新完整核SHA，本阶段不实现共享包缓存。

这些固定源码是方案与反例依据，不是c7超时具体网络根因，也不是新runner实际APT版本/全部Ubuntu补丁已核实的证明。真实版本原件须由新CI提供；APT全来源/签名和供应链公证仍不在本阶段宣称范围。

未访问生产、未合并main、未发布镜像、未在本机安装软件或启动服务。整套企业系统、灰度、生产读回与系统级恢复仍按[项目台账](PROJECT-PROGRESS-LEDGER.md)保留未完成状态。
