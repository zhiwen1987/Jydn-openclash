# P2：固定浏览器原件的真实消费与安全展开验收

本阶段验收通过的范围仅为：隔离 Linux CI 真正强制已审 SHA，取得原 ZIP、安全展开，并由独立命令及 fresh Linux job 重算原件、全部成员 CRC/大小、实际落地文件 SHA 和 Chrome ELF 结构。**没有执行浏览器，不证明取消故障已修复，不是系统或生产验收。**

实际源码提交为 `409aa9c109060cb1248914940e292b4ce0ab9ac7`。本文及[机器证据](evidence/p2-browser-pin-consumption-409aa9c.json)是该源码和原 CI 结果的归档，不代表文档提交又执行了一遍验收。

## 原 run 与实际边界

[原 run 39988647783](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39988647783)，attempt 1，producer `120534356721` 和 fresh `120534599570` 均完成且 success；没有通过重跑覆盖失败。

producer 使用固定官方 HTTPS URL，禁止重定向、环境代理和 CA 覆盖，校验精确长度、generation、MD5 和已审 SHA，再展开。fresh 只下载原 ZIP 工件，通过 `--archive` 在新目录重新强制同一 SHA、重新展开和核验；不复制 producer 的展开树，不伪造第二次 TLS 下载。

历史 [pin.json](../tools/browser-runtime-candidate/pin.json) 原字节 SHA 为 `404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea`，没有修改。其历史 `consumedByExecutionHarness=false` 和运行字段 `null` 保留：本阶段的新证据证明下载/展开工具已消费 pin，不把旧参考字段改成“已启动浏览器”。

## 实际取得与展开

| 对象 | 原件结果 |
|---|---|
| 官方 full CfT 引用 | `157.0.8103.6 / linux64`，不是 headless-shell；版本仍为来源引用，不是运行读回 |
| 原 ZIP 大小 | `202676171` 字节 |
| 原 ZIP SHA256 | `7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853` |
| 原 ZIP MD5（base64） | `5qChIL/Gh+8hZv73vzEakQ==` |
| GCS generation | `1792024099984701` |
| 原中央目录 inventory 摘要 | `40a84f87dd5799295c8a50582ee893af1e284f7e5d2a85e79683f299b688c015` |
| 实际展开成员 | `309`，其中 `301` regular files、`8`显式目录成员；包含隐式父目录后共`11`个物理目录 |
| 实际文件总字节 | `425547397` |
| 实际展开成员模型 SHA256 | `527a3556f1a2db2d89dc0449c77594f2974d46eb54f50ab96d84d8d00ac3e171` |

中央目录摘要和展开模型摘要不是同一对象：后者包含实际文件 SHA、CRC、真实大小和剥权后的模式。两个 Linux job 的完整展开模型一致。

展开前复用原严格 inventory，拒绝路径逃逸、duplicate、link/special、加密和超预算。展开采用 descriptor 相对目录及 O_EXCL 文件创建，不调用 `extractall`；raw-deflate 有界解码要求 EOF、拒绝截断和多余压缩尾部，并重算真实 CRC/大小。数据文件为 `0400`，已审9条 executable 来源白名单为 `0500`，展开目录为 `0500`，输出根为 `0700`；不保留 setuid/setgid。独立 checker 再次解码原 ZIP，另行读取实际落地文件，核对完整闭集、权限和内容。

## 实际 ELF 读回，不等于浏览器执行

```text
path: chrome-linux64/chrome
bytes: 305061192
SHA256: ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444
ELF64 / little / x86_64 / DYN
entryPoint: 124443728
programHeaderCount: 12
loadSegments: 4
```

这是两个 Linux worker 对实际文件字节和有界 ELF 头/程序段的检查，不是 OS loader 或动态库兼容证明。没有 product/revision/protocolVersion 运行读回，不把来源 tag 当运行 revision，也不把结构检查称为补丁成功或浏览器可用。

## 来源、原日志与工件保管

五个运行依赖（pin、consumer、checker、原 acquisition checker、原 acquisition candidate）都与精确 Git 提交原字节绑定；本机再次逐件核对 Git、manifest 和当前文件。原20项合成用例实际只在 producer 执行一次，20通过、0跳过；fresh 拷贝同一原日志，不计为另外20项，也不混入旧门数量。名称与该提交测试 AST 精确相等，排序LF连接、无尾LF的名单 SHA 为 `28d61521916e7bd80da9303a9bb4ec25549fd12d6e984849af1fa1c4e361f103`。

| 工件 | ID / 字节 | 原 ZIP 外壳 SHA256 |
|---|---|---|
| 仅原 browser.zip | `12517205795 / 202676307` | `7845a22c1dda272c1a75bdaa1390182f2a305ab8c9821fc0d3eedf12a6ce125d` |
| producer 小报告 | `12515759562 / 15328` | `4a62d65d0b0a168f155d964e466efed723fcc9835afafdd2a6e937a151b254aa` |
| fresh 小报告 | `12516273045 / 15153` | `7ea62d6281ced7bef7afc54e451cd49baf4d181796caba628c060c49c64a5642` |

GitHub 工件外壳 SHA 不等于内含官方 `chrome-linux64.zip` 的 SHA。fresh 原日志记录原 ZIP 工件下载摘要与 producer 上传摘要一致。两个小包各7件文件，不含浏览器 ZIP、ELF或展开树，本机逐字比对了这些小文件与对应原 artifact member。

producer 的 consumer、独立 checker、两份 stdout 及原 job 日志内两条 canonical JSON 逐字一致：报告`1304`字节，SHA `0e8d93fa920538cf5bb6f4d33242f7f4e65f3e44e77ad1f8693e4025acd44b99`。fresh 对应报告`1300`字节，SHA `bbbc8cc799c5e3a09b1feb54f41ddb70b4c634f034e8371b790bf393360ffc52`。跨 job 报告仅 `mode` 不同；manifest 仅 `mode/httpReceipt` 不同，fresh 的 `httpReceipt=null`。

本机审阅目录：

```text
C:/Users/Administrator/AppData/Local/Temp/chengwang-pin-consumption-409aa9-audit-550ca2f3b0324790b8d5b6ca3462996c
```

其中保留两份小包原外壳、展开的小报告、GitHub API原 run/artifact metadata及原 job 日志（保留原ANSI，不是 `gh run view` 添加字段前缀的文本）。完整指纹及路径见机器证据；临时目录不是长期备份承诺。

## 未完成与不能外推的部分

本机没有下载、展开或重算202MB原 ZIP及305MB ELF。全量解码、CRC和落地文件 SHA 重算在两个 Linux CI job；本机重验的是小工件外壳、报告/manifest模型、原日志、有限合成事件及精确Git来源。fresh 复用同一已绑定校验实现，不是异构算法证明或 publisher 签名。GCS CRC32C字段仅作为HTTP观察字段校验，没有冒称本机独立CRC32C计算。

下一阶段仍需把匹配的 alpha Playwright 包固定来源/完整性并隔离取得，启动前复制并强制实际 ELF 身份，再做真实浏览器 product/revision/protocolVersion 读回、no-store 分块正例及超限/HTTP截断/显式 abort 负例、候选完整CDP/PW原门和新订阅页真实E2E。`1.64.1`旧门未被替换，alpha不称稳定生产版本。

本阶段没有生产部署、主分支合并或正式Registry发布；系统整体目标仍未完成。
