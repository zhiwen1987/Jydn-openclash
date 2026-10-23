# P2：固定候选浏览器流矩阵验收记录

日期：2026-10-24（Asia/Shanghai）。源码 `72916551bb2339f00f2944d9dfb2e15b680cbeee` 的**隔离协议矩阵已验收**；不是实际产品页面验收，不是生产上线。全部摘要、job/artifact ID 与缺口见[机器证据](evidence/p2-browser-stream-matrix-7291655.json)。

## 实际完成

[原运行 39993513218](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39993513218) 为新源码 attempt 1，不是重跑失败任务。以下五项均实际终态成功：

| 范围 | job ID | 独立验收 |
| --- | --- | --- |
| 冻结合成合同 | 120551013294 | 实际 104 项：32 Node＋72 Python，0 skip；逐条原输出、冻结名单和计数重算 |
| 实际 Chrome/CDP | 120551089752 | 正常 TLS、固定五场景、原件独立 CLI |
| 实际 Playwright | 120551090176 | 原生 persistent context/page.evaluate，非 mock 路径 |
| fresh Linux/CDP | 120551472477 | 下载原 producer 原件，纯离线重算，报告逐字节相同 |
| fresh Linux/Playwright | 120551472587 | 同上，没有新跑浏览器替换原记录 |

两个适配器实际观察到 `Chrome/157.0.8103.6`、revision `@41520584daa68d0040db7746ae562a0ff82187f6`、protocol `1.3`。已审 ZIP SHA 在展开前被强制消费，安全展开后再读回实际树；复制的 ELF、实际进程 `/proc/PID/exe`、argv、PID/start tick 与版本读回相互绑定。ELF 为 305061192 字节，SHA256 `ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444`。每引擎校对 829 个 Git 原 blob。

`playwright-core@1.65.0-alpha-2026-10-23` 仅在独立开发/CI 包使用，没有替换原稳定工具或部署到生产。历史 acquisition pin 文件不回填“已执行”；本轮实际消费与执行另有原记录。

每个引擎均实际完成：

- `split-success`：11 字节、服务端 6/5 分段；页面 EOF/JSON/摘要、网络 FINISH、主机响应摘要一致。
- `boundary-success`：恰好 1MiB，严格预算内成功，三层一致。
- `oversize`：1MiB＋1，页面明确拒绝、取消，不当作成功 EOF。
- `truncated`：声明 11 字节但仅收到 6 字节，读取错误与网络失败，不补造响应。
- `abort`：真实 AbortController、AbortError、网络 ABORTED 与服务端 peer close。

每引擎 6 请求、18 条网络事件、24 条服务端事件；无重试，维持 `no-store`、原 1MiB 上限和正常证书校验。服务端 write 返回不等于线上 ACK 或抓包。七个 driver 错误计数均 0，Chrome/控制器/服务器的实际正常退出码均 0，无强制信号、无存活自有进程。

实际运行仅发生在 GitHub Linux CI 的私有网络/挂载/PID namespace，低权限 UID、空 capabilities、NNP、资源上限、lo-only、只读工具/源码和私有 NSS/XDG 信任区。未改宿主 CA 或生产网络。独立 checker 用公开证书在原观察时刻离线核对签名链、IP SAN 和有效期；没有忽略时间或证书错误。

## 原件及四方独立读回

根和代理分别核对5个原小包 SHA 与 GitHub artifact API digest 一致；根自己下载目录中的41个文件也逐字节等于ZIP原始条目。没有下载本机浏览器 ZIP/ELF，包内无私钥、profile 或浏览器二进制。

| 原小包 | artifact ID | 字节 | SHA256 |
| --- | --- | ---: | --- |
| contracts | 12517839297 | 6594 | `933409ed226b3765a0d26f4a26cb0293cae0bbfbc71abba5c55b2300b09ad30e` |
| CDP producer | 12519046859 | 115035 | `790d5721b05b872b9344c56e8d61d818fd9a041ece05fdaa41528c5c05f5d0c1` |
| Playwright producer | 12517958976 | 115667 | `ee113c18f93d5bd6cbf368ccb48b3a5cf42dc7f8353e0f297fddde128b0cf664` |
| CDP fresh | 12519096606 | 1459 | `a0bb1c1b82d104964ae6afbc9d059d482a54cf2b0e261a289f716be2318deeeb` |
| Playwright fresh | 12518637523 | 1463 | `89e91a99b4b2bed51564865d718dc8b1d693aedf7537f52fe76f1cd026cff299` |

根集成者与独立代理分别使用精确 Git checker（29466 字节、SHA256 `70b2401e6048735fe55a330304a14c843bbf9e39095827978a7cd8411c5986ef`），各自从原小包完整执行两条 CLI，均 exit 0。Windows 仅使用纯 CPU Git/JSON/摘要和预装 Git OpenSSL 离线验签，不运行浏览器、服务端或安装依赖。以下报告均满足 **producer＝fresh Linux＝根本机＝代理本机逐字节一致**：

| 报告 | 字节 | SHA256 |
| --- | ---: | --- |
| CDP | 1813 | `0cd44d20d5d67c5a7ab9b85b5b1e198ca3b1beb367d4486221e407296df0b424` |
| Playwright | 1813 | `0f0d9fb809239b4ff45edb05829ce2e83e4b89b086e1f428e089ecd2cca87e1c` |

104 项原输出的独立核验报告为 1595 字节、SHA256 `d9bddea2fdd7442cea657932b803f94cb522e0ad8731f90fa0cb8d621114a04c`，根/代理均与 CI 原报告逐字节一致。新增 8 项 native 回归单独计入，本阶段计数不并入旧80、新56或产品测试。

## 首轮失败保留与修正依据

旧源码 `de875c014124e83a768c178a67df136b933b1d4b` 的[原运行 39992474501](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39992474501) 仍为 failure。旧合同 96 项通过；两个实际运行 step 成功，但原独立 checker 均拒绝、退出 1，fresh 跳过。代理对旧两引擎、根对旧PW用精确原 Git checker 完整重放，均在 `verify:315 → validate_network:161` 拒绝。不能把新源码通过回填为旧源码通过。旧 3 个原 artifact 的 ID/完整 SHA 已保留在机器证据。

原观察中的 START/HEADERS/FINISH 微秒值：

| engine / request | START | HEADERS | FINISH |
| --- | ---: | ---: | ---: |
| PW DOCUMENT | 62746256 | 62794278 | 62793624 |
| PW split | 62817809 | 62861753 | 62861394 |
| CDP DOCUMENT | 165719997 | 165767484 | 165766611 |
| CDP split | 165784238 | 165827750 | 165827492 |

实际事件到达顺序仍是 START→HEADERS→FINISH。针对代码不明确之处，根与代理直接读取 Chromium 固定 Git `41520584daa68d0040db7746ae562a0ff82187f6` 的原始源码（118872 字节，SHA256 `a21e526cc2008a2f505f9d6c4fe51f1afb1f657919205a7937eb06510929b0e4`）：[responseReceived 1678–1683](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_network_agent.cc#L1678-L1683) 用 dispatch Now；[loadingFinished 1803–1809](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_network_agent.cc#L1803-L1809) 用保存的 monotonic_finish_time（null 才用 Now）；[loadingFailed 1853–1858](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_network_agent.cc#L1853-L1858) 用 dispatch Now。

因此只取消成功 FINISH 必须晚于 HEADERS dispatch 的错误比较；仍保留 START≤HEADERS、START≤terminal、HEADERS≤FAIL，以及严格事件序号/身份/字节/状态/摘要/TLS/正常退出全部门。不排序或篡改原时间，不加经验容差，不忽略失败。该修正解释本轮 verifier 拒绝，不能推断其他历史偶发取消的唯一根因。

另外，初次工具 JSON 转义显示曾引出 argv 分隔符疑问；原 Git AST 独立求值证明一直是 NUL `00`，三个进程 argv SHA 重算正确。这一候选判断已明确撤回，没有修改原本正确的 argv 逻辑。

## 尚未完成与下一退出条件

本阶段没有把候选接入实际产品安全 reader、新订阅页面或旧产品全门，也没有截图/视觉/交互验收。下一阶段须实际接线，再按原完整浏览器门与订阅页流程逐项验证，不能用这次合成协议矩阵替代。

历史偶发取消根因、已运行二进制的补丁祖先关系、长期稳定性、可复现工具链构建、独立发布者签名和整套系统交付均未证明。fresh 使用同源 checker，不是异构实现或供应商远程证明。

另行复核的[父门39993513211](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39993513211)已success：根/代理重放精确Git7 checker和原HTTP日志，ordinary/race各2644 Test恰一次run/pass、0 Test skip/fail，各另12 Fuzz单独计数；本机未执行Go。[订阅39993513263](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39993513263)两Linux完整原门均success；代理对原20文件/46 captures/4 epochs/26连接/102事件/819 Git做纯语义和离线证书复核通过，80实际单位名单0skip；根/代理另核原两包API摘要及producer/fresh报告逐字相同。Windows完整POSIX custody仍拒绝 `public-file-open-race`，没有放宽或冒称本机完整通过。这些是独立原门证据，不是由矩阵通过推定。旧产品浏览器与镜像门尚未用本候选重新执行。

未合并 main，未发布正式镜像；未接触旁路由、爱快、DNS、Kuma、ERP 或其他生产设备。生产授权继续 BLOCKED，整体项目保持未完成。
