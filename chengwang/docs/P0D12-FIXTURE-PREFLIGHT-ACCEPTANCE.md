# P0-d12 外部生命周期 fixture 前置门验收（2026-10-23）

**结论：前置门已实现并在隔离 Linux CI 验收；D12 真实产品自动刷新和异常恢复矩阵仍未完成。未部署、未合并 main、未改变生产。**

本记录保留605代码轮的历史边界与计数。后续957代码轮已另行验收真实镜像自动刷新/正常重启子门，见[后续子门结果](P0D12-PRODUCT-LIFECYCLE-ACCEPTANCE.md)；异常恢复完整矩阵仍未完成，不回写本轮报告中的false字段。

## 1. 实际版本与原始证据

接受的代码为 `605f67eb63b2a9c738ce703f9b6f78d7a71179b7`。本文件的后续文档归档提交不是另一份已验运行镜像。

- [绑定流水线 39834169047 / job120017946250](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39834169047/job/120017946250)：completed/success，head 为上述代码。
- [父流水线 39834169008 / job120018134988](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39834169008/job/120018134988)：completed/success，同一 head。
- 工件 `12450063281` / `image-binding-39834169047-1`，151 文件，ZIP 4,179,055B，GitHub SHA256 `5323d63b10793fbb39087a6753a029ca2e15e7889d4c93c118b08aa1fe2d66b8`。工件保留期14天，不把临时工件当永久灾备。
- 主代理和独立代理分别下载、重算；`product-lifecycle-preflight.json` SHA256 `a6218f6eac7e4e6f36afd417fdce667a07c3b85dae3fbf9de886c9dd1a3e30ba`，两方结果一致。
- 主代理实际下载的 binding job 原日志 1,794,879B / SHA256 `d5166c86c4aed3378267674ea1d3834d71424bd67a0afc2ebdc4393877eec0c0`；父 job 5,447,215B / SHA256 `90ff359f0fe8064736febf6fddb3e5e97691ede27585fe9e09f6eb207df6492e`。

主代理本地工件目录：`C:/Users/Administrator/AppData/Local/Temp/chengwang-p0d12-final-605-4bca504a69fd429cbb5b5856376e0202/evidence`。这是当前开发机的临时验收副本，不是生产目录或持久归档承诺。

## 2. 新门实际执行结果

| 套件 | 实际结果 | 范围 |
| --- | --- | --- |
| lease | 20/20，零跳过 | 17 个真实 Linux 进程场景、3 个 shape 检查 |
| feed | 33/33，零跳过 | 19 个真实 Linux/TLS 场景、14 个 shape 检查 |
| 独立 transcript/cleanup checker | 13/13，零跳过 | 合成缺项、重复、重命名、skip、伪 marker、清理冲突等拒绝反例 |

不能把这66项全部称为真实产品测试。它们验证的是外部 fixture 和其检查器；产品镜像尚未接入这两套新 fixture。

实际 Linux helper 均为 UID/GID10001、capability 五集合全零、NNP；root 只为可信测试 orchestrator。租约真实执行读放行/写阻塞/release/TERM/SIGKILL/deadline，原日志字节不变；失败路径拒绝错误目录/文件权限、owner、链接、FIFO、替换 inode 和 control。

源站实际执行正常 CA/SAN TLS、错误 CA/SAN 在 HTTP 前拒绝、peer 证书 SPKI 身份核对、固定路径和安全日志、单调 epoch/同代原 bytes、并发 oneShot、坏 plan/body/文件拒绝，以及 TERM/INT/deadline 的关闭与 join。ready 为原子 no-replace 发布；日志缺失/损坏不能冒充零 HTTP，顺序断言使用落盘屏障，八个慢 TLS worker 经 `/proc/<pid>/task` 观察后才停止。

cleanup SHA256 `3363e8b13e08abee4f08c96eff4db5f3bffde39a60f4873bb29325b9b2a05e05`。原始字段为 `privateTreeRemoved=true/testExitCode=0/hostTmpTouched=false/parentMountNamespaceChanged=false`；仅在子 mount namespace 清理本轮专用 backing tree。source/cache 只读，只有 loopback、无默认路由；不宣称 root harness 的宿主 Unix sockets 已隐藏。

两方逐项核对8个前置门源文件摘要，且 checkout568 + child79 = 647条记录（568个唯一路径）在运行前后完全相同、逐 Git 原 blob 匹配。未做 CRLF 归一化后冒充原 bytes。

## 3. 原回归未缩减

- 子模块普通/race 各700项、8包，Registry普通/race各3项、1包，零跳过；原检查器实际重放通过。
- 父模块普通/race各2320个完整测试名 run/pass 对，零失败/跳过，两轮集合 SHA256 均 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。
- 原 D11 的49份关联输入重新独立重算通过，canonical outcome 一致（SHA256 `dfcc117db533cae03b7caf005fca20378cef98a2cb5383b46fe255c29f8b392e`）。44个 Registry 快照、2次真实产品成功读取、18个零请求窗口、正常停止/重启及精确清理保留；**这仍是未启新刷新源站的原 D11 回归**。
- 原 HTTP40 / HTTPS45 / 真镜像 HTTPS45 浏览器门通过，D10五次正常退出、四类启动拒绝及清理通过；本阶段没有新增人工视觉验收或其他浏览器兼容性证明。

## 4. 失败记录不删除

`56fa411` 首次接线后，补上最后一个顺序事件屏障形成 `d35c2b8`；56流水线由既有 concurrency 取消，不算测试通过或测试失败。

`d35c2b8` 的 [39833779150/job120016624253](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39833779150/job/120016624253) 实际失败：lease19/20、0skip。control 目录变成 root-owned0700 后，低权限目录 open 已拒绝，但外层把 EACCES 错归为 `UNSAFE_FILE`，严格测试要求 `UNSAFE_DIRECTORY`。feed/Go/真实镜像门该轮未执行，不能继承或补报通过。

失败工件 `12449372993` / ZIP249,946B / SHA256 `b88913297dee7d2114dff1dc95bbe6d443d1caabdd01e9319624c47acb001355` 保留。两方确认清理成功且 `testExitCode=1`，无 `preflight.json` 或总 PASS；该失败同时提供了真实失败路径清理证据，但不等于已验证所有超时强杀分支。

605只把目录 open 异常局部分类为 `UNSAFE_DIRECTORY`，目录 symlink 测试同步唯一的正确枚举；拒绝、退出码、权限、无 ready 断言与20项全集保留，未放宽为任意错误、未跳过或删除测试。

## 5. 未完成项与下一步

三个字段明确为 false：`actualProductLifecycleProven`、`productAutomaticRefreshProven`、`productImageFaultInjectionProven`；`fixturePrerequisitesOnly=true`。

下一步才是同轮真实默认镜像的独立 D12 lifecycle gate：后台 actor 自动刷新/撤销、陈旧拒绝和恢复、重启重新确认；真实 API 在途外部屏障、指定进程终止、健康两库补审计和二次启动幂等；预置中间态与真实中断分别报告。详见[D12合同](P0D12-LIFECYCLE-CONTRACT.md)。不得把 SIGIO marker 单独当指定产品故障点证据，也不得把 source peer SPKI 身份核对当产品已执行固定 SPKI 拒绝。

未新增产品 fault HTTP/env/config 开关，未改实际产品 Go 运行逻辑、原 D10/D11 合同或正式发行链。九项恢复 blocker、企业身份/正式密钥和 Registry/发布部署、多内核/DNS/订阅/业务执行与长期 soak 等原缺口不解除。仍 `authorization=BLOCKED/production=false/deviceActionsExecuted=false`，不宣称无 bug、免维护、物理坏盘/断电自修或全项目完成。
