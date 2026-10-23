# P2：固定浏览器的正常 TLS 流矩阵

状态：修正版 `7291655` 两真实引擎及fresh Linux原件重放已通过，根/代理完整CLI与CI逐字相同，见[实际验收记录](P2-BROWSER-STREAM-MATRIX-ACCEPTANCE.md)。首轮 `de875c0` 因独立 verifier 的时间语义错误拒绝，原失败保留。这里只验证独立合成协议场景，**不是产品页面、新订阅交互、历史故障唯一归因或生产验收**。

## 为什么单独验证

此前采集出现过页面流到 EOF、网络层却取消的现象，尚未证明唯一根因。参考 [Playwright #42742](https://github.com/microsoft/playwright/issues/42742) 和已归档的 Chromium 上游测试设计，单独核对三层：页面实际读取、原生 CDP 请求终态、主机侧 `Network.getResponseBody`。相似上游问题不当作本项目已经确诊。

历史 acquisition pin 不改。先执行真实 SHA 强制消费和安全展开；再把同一 ELF 复制到 root-owned 只读工具区，并在运行前同时核对复制字节、实际 `/proc/PID/exe`、argv、PID/start tick 和 `Browser.getVersion`。版本与 revision 是预期验收门，不能在真正运行前宣称已观察到。

## 固定矩阵

每引擎一次固定顺序、无自动重试：文档一个 GET，随后五个 GET。所有场景 `Cache-Control: no-store`，不使用 `response.json()`、克隆响应、mock fetch 或忽略证书错误的替代路径。

| 场景 | 固定输入 | 必须观察到 |
|---|---|---|
| split-success | 11 字节 JSON，6/5 分段，20ms 间隔 | 页面 EOF/解析/摘要正确；网络 FINISH；主机原始响应摘要相同 |
| boundary-success | 恰好 1MiB JSON | 严格大小边界内成功，三层一致 |
| oversize | 1MiB+1，HTTP/1.1 分块，无 Content-Length | 实际读到超限字节，拒绝并尝试取消；不冒充 EOF 成功 |
| truncated | 声明 11 字节，仅写 6 字节后关闭 | 实际六字节前缀及读取错误；网络失败；不补造完整内容 |
| abort | 写 6 字节，页面明确 AbortController.abort | 实际 abort 请求/信号/AbortError，网络 ABORTED，服务器观察 peer close |

超限允许接收已在取消前完整抵达时网络 FINISH，或由取消引起 ABORTED；不允许把任意网络错误都当作正常。截断前的20ms是固定服务端测试窗口，不保证任何负载下的确定调度；未观察到约定前缀就拒绝验收，不以重跑或调大窗口消除失败。

服务器记录24条应用层事件，浏览器记录18条原生网络事件；应用 write 返回的字节和 HTTP 分块字节**不是 TLS 线上 ACK 或抓包证明**。各请求内分别校核顺序，不能假定不同服务器线程的 COMPLETE 与下一 REQUEST 不会交错。页面 elapsedMs 与 CDP 单调时钟不相减。

## 隔离、信任与退出

两个真实适配器：原始 Chrome/CDP 和固定 `playwright-core@1.65.0-alpha-2026-10-23` 的原生 persistent context/page.evaluate。alpha 仅在独立开发/CI 包使用，不替换旧稳定工具包，不向生产部署。

仅 GitHub Linux CI 执行实际下载、展开、安装和浏览器/server/netns。Windows 本机只做 AST/纯 CPU/合成检查，不下载真实浏览器 ZIP 或 ELF。没有 Browser 插件，采用已获准的常规 CDP/Playwright 路径；本阶段不宣称截图或产品 UI 视觉验收。

每个引擎使用独立 mount/net/PID namespace、lo-only、无默认 IPv4/IPv6 路由、只读源码/工具、低权限 UID10001、空 capabilities/补充组、NNP 和硬资源上限。私有 `/var/tmp` tmpfs、私有 home/XDG NSS `C,,` 根证书；不改宿主 CA、HOME 或网络。正常 CA/SAN/有效期由实际浏览器验证；独立 checker 再以公开证书离线验签，在文档请求的记录时点验证 `127.0.0.1` 和有效期。依据 [OpenSSL 官方验证选项](https://docs.openssl.org/3.2/man1/openssl-verification-options/)，`-trusted` 禁用默认信任来源，`-attime` 不禁用时间验证。

Node/服务器/Chrome 的实际身份由控制器放行前的 barrier 固定。launcher 的真实 wait、独占原子退出记录、控制器退出、服务器退出、namespace PID1 孤儿回收全部必须满足；关闭命令成功不等于退出成功。失败/超时永不伪造 exit 0，已发布的安全原件和固定枚举诊断尽量保留，畸形私有输入不导出，验收必须拒绝。外层 watchdog 使用 `unshare --kill-child=SIGKILL` 限定本次私有 namespace，不作用于宿主服务。

## 原件与独立验收

成功原件闭集8个：`driver.json`、`network.jsonl`、`server-events.jsonl`、`processes.json`、`isolation.json`、`certificates.json`、`inputs.json`、`pin-consumption.json`。不上传浏览器 ZIP/ELF、展开树、私钥、profile 或原始私密 stderr。失败原件可带 `failure.json` / `failed-host-readback.json`，只能诊断，不能通过成功闭集。

源码完整 Git blob 列表、复制输入摘要、真实 ELF/Node 进程 hash、正常 TLS、协议模型和正常退出均由独立 Python CLI 校核。fresh Linux job 下载原件重放相同 CLI，与 producer 报告逐字比较。可信 CI 的 `/proc` 与父进程 wait 不是抗恶意同 UID 或独立供应商签名的远程证明；Python/Node/NPM/系统库也未独立重建。

首轮新合成测试共32 Node +64 Python（24服务端/launcher、24模型、8严格类型/TLS反例、8失败保管），原CI已实际核对96事件、0 skip；修正版另加8 native回归，共104，不能把尚未运行的新CI计数写成首轮结果。它们不替代实际浏览器矩阵，不并入原80/新56或旧产品门计数。

## 首轮拒绝与精准修正

[原 run39992474501](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39992474501)，源码 `de875c014124e83a768c178a67df136b933b1d4b`、attempt1。两个真实引擎执行步骤成功，独立 CLI 均拒绝，fresh 未运行，故整体失败，不能后补 PASS。

PW 原 DOCUMENT 的 START/HEADERS/FINISH 为 `62746256/62794278/62793624`，split 为 `62817809/62861753/62861394` 微秒；实际接收 seq 仍按 START→HEADERS→FINISH。根完整旧 Git checker 重放确认在 `validate_network` 的 `HEADERS.timeUs <= FINISH.timeUs` 拒绝。

查阅固定版本 [responseReceived实现](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_network_agent.cc#L1678-L1683)、[loadingFinished实现](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_network_agent.cc#L1803-L1809) 及 [loadingFailed实现](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_network_agent.cc#L1853-L1858)：HEADERS/FAIL 使用 dispatch 的 Now，FINISH 则携带先前保存的 monotonic_finish_time。相同时钟不代表不同语义的字段按发送顺序数值递增。

仅去掉成功 FINISH 的这条比较；START≤HEADERS、START≤terminal、FAIL 的 HEADERS≤FAIL、严格到达 seq/三条事件/请求身份以及全部字节、状态、摘要、TLS和正常退出不变。不排序、不改原时间、不加经验性容差，不忽略失败。新8回归还确认既有 argv SHA 的 AST 分隔符原本就是 NUL `00`；工具JSON转义显示不是源码缺陷证据，没有修改这段正确逻辑。本修正只解释本轮 verifier 拒绝，不证明其他历史取消的唯一根因。

本矩阵退出条件已按上述记录完成。下一阶段须将验证过的候选接入**实际产品**安全 reader 与新订阅页面端到端流程，再运行原有回归。本矩阵成功仍不证明历史偶发取消的唯一归因、长期稳定性和整套产品上线。
