# P2-06b 前置：真实身份与候选原包保管

状态：实现及本机有限合成测试已完成，真实 CI 与候选获取待运行；不是修复完成，不是新订阅页浏览器验收，也不是上线。上一轮 `ad3e4db` 的取消请求失败继续保留，不能被本阶段身份观察或下载成功抵销。

## 为什么分两步

按用户要求先查官方 GitHub 源码及问题。相关 [Playwright #42742](https://github.com/microsoft/playwright/issues/42742) 指向 Chromium 已合并的 [`62473ad0f747e245e514c93e741bb8e168a2a207`](https://chromium.googlesource.com/chromium/src/+/62473ad0f747e245e514c93e741bb8e168a2a207)。这是相似案例，不是本项目唯一根因证明。现有探针固定 Playwright `1.64.1`，但复制宿主 Chrome，不能靠升级 npm 包推断浏览器已替换。

已只读查实可取得的隔离候选：`playwright-core@1.65.0-alpha-2026-10-23` 的固定 gitHead `20a2087ea43412b90c172c88faef80786ee18b8b` 对应 full CfT `157.0.8103.6/linux64`，浏览器 registry revision `1251`。这是 alpha，只用于隔离兼容验证，不是稳定生产版本。官方 [CfT metadata](https://googlechromelabs.github.io/chrome-for-testing/157.0.8103.6.json)、[npm metadata](https://registry.npmjs.org/playwright-core/1.65.0-alpha-2026-10-23)、[固定 Playwright 清单](https://raw.githubusercontent.com/microsoft/playwright/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/browsers.json) 与 Chromium tag/fix 原文一起保管。源码包含修复不等于已运行的二进制包含修复，更不等于本项目已修复。

官方没有提供该 ZIP 的 SHA-256，因此候选合同中保持 `null`，绝不编造。先在 GitHub Linux CI 获取原 ZIP，fresh Linux 从同一原 artifact 重新核验，再由根集成者审阅实际字节摘要。只有后续独立提交固定该 SHA 后，才允许执行该候选。当前获取 workflow 不解压、安装或执行浏览器，不取得实际 npm tarball；只保管其官方 metadata。不会下载浏览器到本机。

## 本阶段接线

1. `browser-identity.mjs` 在真实 `actualChrome` 后单点输出闭集身份行：engine、fixture、product、revision、protocolVersion、PID、startTicks、argvSHA256；不保留 userAgent、jsVersion、任意异常或私有路径。
2. 外层受信 supervisor 单独发布 `lab/browser-identity.json`，绑定实际已复制 Chrome ELF 的字节数和 SHA，不修改旧 driver schema、捕获集合或八个零错误计数。
3. 新身份 CLI 重新运行原 backend22、build 和 process 子门，核对原 captures 字节、正常退出、namespace/权限、argv/ELF、源 Git 原 blob，再报告 `processBindingVerified=true`。不调用旧 driver 的零业务错误门，故失败浏览器仍能留下身份观察；该报告始终 `browserAcceptanceProven=false`、`patchAncestryProven=false`。纯字段函数本身只报告 `identityFieldsMatched=true`、`processBindingVerified=false`。
4. 原80合成门保留全部名字指纹。新增 report 邻接 `.raw` 目录，保管 Node 原 TAP/前端 JSON、Python 逐次 RUN/PASS 与原 verbose log、执行结果及 manifest；独立 checker 从原件重算，不接受仅有 summary 的 PASS。正常9文件，真实空输出只记空摘要，绝不补造换行文件。
5. 新56合成门独立计数：Node 身份20、Python 身份12、原件检查器24；不并入旧80、旧32或产品前端190。新获取工具的18合成项另计。
6. 诊断与身份合并日志上限从327680改为329728，仅增加单条闭集身份行及 framing 容量；512事件、每事件512字节、业务响应1MiB、超时、正常 TLS/no-store 与原错误计数不放宽。

## 本机已实际执行的有限验证

- 原80首次执行及首次独立原件重算均通过，0跳过；五个原测试文件运行前后 SHA 一致。Node `v25.2.1`、Python `3.12.10`，不是 CI 的固定 Node22，也不是真浏览器。
- 根端最终新56真实原输出已逐项计数并独立核验，0跳过；身份类型、浮点 startTime、argv/TLS bypass、ELF替换、production标记、未知 driver 字段及外侧 Python 方法名伪造有拒绝反例。最终读回在 `C:/Users/Administrator/AppData/Local/Temp/chengwang-identity-final-local-951_pahp`；不是只引用审查前通过。
- 获取18合成项根端实际通过，0跳过；使用小型合成 ZIP，没有下载或执行浏览器。
- 两条 workflow 的16个 Bash run块仅做 `bash -n` 语法解析通过；本机没有 YAML parser，人工核对 YAML 不冒充完整 Actions 执行。
- 首轮开发测试曾发现测试夹具默认参数、Windows stat 时间语义和解码类型遗漏，均保留为开发过程，不冒充一次性真实 CI 成功。不放宽原 Linux 正式门来迁就本机。

本机原80证据：`C:/Users/Administrator/AppData/Local/Temp/chengwang-status-contracts-local-1786e842099548ee98a2c2d251cb01b3`；`contracts.json` 8634字节、SHA `d549925b79f84e35e318165e76e0dd78e053c0759b847f2337a47da8935d394c`；独立 `verified.json` SHA `46c899cb5f30bc2dabda53c74e07e378d4e92919345a4dc6655b47490405ceeb`。这只是合成合同的原件，不是原始互联网或浏览器成功证据。

## 必须继续的验收顺序

| 阶段 | 当前证据边界 | 后续通过条件 |
| --- | --- | --- |
| 原浏览器身份/80原件 CI | 已接线，待执行 | 两引擎各自实际侧录及原门结果；保留失败 |
| 候选 acquire/fresh Linux | 已实现，待执行 | 官方9 metadata、原 ZIP、来源/大小/MD5/GCS generation、独立 SHA/inventory 重算；报告只称取得未执行 |
| SHA 审核与执行 pin | 尚未执行 | 根端审阅 CI 原证据，再另起提交固定真实摘要；不覆盖现有稳定回归工具链 |
| no-store split-stream 矩阵 | 尚未实现/执行 | 正例及超限、HTTP截断、显式 abort 负例，正常 TLS/原1MiB预算，不忽略取消 |
| 候选完整 CDP/Playwright | 尚未执行 | 原 backend/build/process/浏览器八个零错误门全部通过并独立重算；身份不是替代 |
| 新订阅页真实 E2E | 尚未实现/执行 | [原双浏览器验收计划](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)全部操作、网络/审计及视觉/交互真实证据 |

公共 TLS/官方 metadata/MD5/GCS generation 不是发布者签名；fresh job 复用同一 Git 绑定检查实现，不是异构算法证明；ZIP inventory 不解压或逐成员重算 CRC。能力、生产授权与整体交付状态保持[总台账](PROJECT-PROGRESS-LEDGER.md)的未完成边界。未合并 main，未发布镜像，未接触路由器、服务器或生产网络。
