# 固定浏览器获取候选：仅隔离 CI，不执行

此目录仅解决“取得哪个官方原 ZIP、其字节是什么”的证据缺口。它不是浏览器测试、不是本项目修复验收，也不是生产发布。保留现有 `playwright-core@1.64.1` 原门不变。

候选是开发/CI 的 `playwright-core@1.65.0-alpha-2026-10-23`（Node >=20、Apache-2.0、固定 gitHead）匹配的 full CfT `157.0.8103.6/linux64`，不是 headless-shell。alpha 不得称为稳定生产版本。

## 固定来源与可信边界

精确 URL、已只读观察的 ZIP 大小/MD5/CRC32C/GCS generation、Playwright 清单和 Chromium fix/tag/included-in 都在 `candidate.json` 中。官方 metadata 没有 SHA-256，因此合同中的 browser SHA-256 必须保持 `null`。首次可信获取后才能另起提交，把实际取得且经审阅的 SHA-256 用于执行门；此工具不会自动修改合同或运行浏览器。

- [官方 CfT 版本及下载](https://googlechromelabs.github.io/chrome-for-testing/157.0.8103.6.json)
- [精确 npm 发布 metadata](https://registry.npmjs.org/playwright-core/1.65.0-alpha-2026-10-23)
- [固定 gitHead 浏览器清单](https://raw.githubusercontent.com/microsoft/playwright/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/browsers.json)
- [官方 Chromium tag](https://chromium.googlesource.com/chromium/src/+/refs/tags/157.0.8103.6)
- [修复包含查询](https://chromium-review.googlesource.com/projects/chromium%2Fsrc/commits/62473ad0f747e245e514c93e741bb8e168a2a207/in)
- [上游问题](https://github.com/microsoft/playwright/issues/42742)

校验 included-in 包含精确 tag、tag commit、修复关键代码顺序、新增上游回归用例 Git blob、fix tree_diff 关联。这证明已公开源码包含修复；不证明实际浏览器已执行，也不能独自证明本项目故障根因。CfT `revision=1717349` 是分支/base position，不是 `Browser.getVersion.revision`。后者必须在下一阶段实际启动后读回。

公共 TLS 与官方 metadata/MD5/CRC 字段提供本次获取来源与传输检查，不等于 publisher 签名、可重现构建或硬件信任。fresh verifier 从原文件独立重算，但复用已 Git 绑定的校验实现，不宣称异构实现的独立数学证明。

## 隔离 GitHub Linux CI 使用

所有五个源文件先提交，`SOURCE_COMMIT` 必须为包含它们的完整40位提交号。两次命令都核对这些源文件当前原字节与 `git show SOURCE_COMMIT:path` 完全一致；不得靠未提交工具生成正式证据。

```sh
python3 chengwang/tools/browser-acquisition/test_acquisition.py
python3 chengwang/tools/browser-acquisition/acquire_browser.py \
  --repo "$GITHUB_WORKSPACE" --source-commit "$GITHUB_SHA" \
  --output "$RUNNER_TEMP/browser-acquisition"
python3 chengwang/tools/browser-acquisition/check_acquisition.py \
  --repo "$GITHUB_WORKSPACE" --source-commit "$GITHUB_SHA" \
  --evidence "$RUNNER_TEMP/browser-acquisition" \
  --report "$RUNNER_TEMP/acquisition-producer-check.json"
```

第二个 fresh Linux job 下载原 artifact 到一个全新目录，再执行同一个 checker，报告放在证据树外的全新文件。不能把 artifact ZIP 外壳 SHA 当 browser.zip SHA；应保留原 artifact、内含 browser.zip 和原 metadata。workflow 设置总超时；Python HTTP timeout 不能保证操作系统 DNS 调用的绝对上界。获取主程序要求 GitHub Linux CI，使用默认公共 TLS、禁环境代理/重定向、按总/单请求/字节预算 GET，输出0700目录，文件 O_EXCL/0600，不覆盖既有文件。下载失败留下部分原文件，缺少最终 acquisition.json 不得视为成功；不自动重试/换源。

证据树闭集共11个 regular 文件：

```text
browser-acquisition/
  browser.zip
  acquisition.json
  sources/
    cft-version.json
    npm-package.json
    pw-browsers.json
    pw-registry.txt
    chromium-tag.json
    fix-included-in.json
    chromium-loader.b64
    chromium-webtest.b64
    chromium-fix.json
```

新验收 JSON 报告必须在该树外。输出枚举明确为 `ACQUIRED_NOT_EXECUTED` / `ACQUISITION_VERIFIED_NOT_EXECUTED`。ZIP 仅中央目录/本地头 inventory，不解压、不安装、不执行；拒绝 duplicate、link/special file、traversal、加密、异常方法、member overlap、超过4096成员、超过1.5GiB声明解压量及超过300倍单成员压缩比。CRC 在 inventory 中记录但不解压重算；不能把“目录安全检查”说成逐成员解压内容或运行验证。

## 新合成门

`test_acquisition.py` 固定18个 unittest 名称，排序后以 LF 连接、无尾LF的 SHA-256 为 `0558c8dc1ef5c52b839bc81f30047b1b242ad67b2dfe67a0c89ffa81c1b59f9a`。全部使用临时合成字节，不发 HTTP、不执行浏览器/Go，不与旧80/32辅助用例合并。metadata 正反例使用明确合成的 regression blob 注入纯 validator 接缝，实际入口 `load_candidate` 仍固定真实官方 blob；不能把合成 metadata 检查冒充真实上游获取。Windows 改写合成文件可触发 lstat/fstat ctime 不一致，负例允许 fail-closed `FILE_CHANGED` 或 MD5 拒绝；正式 Linux CLI 的完整文件身份检查没有放宽。其通过仅证明这些有限校验反例被拒绝，不证明官方下载或真实浏览器已验收。
