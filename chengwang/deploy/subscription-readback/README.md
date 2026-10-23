# P2-05b：独立订阅产品链路验收（候选，首轮失败保留）

这是 CI 专用实验，不是部署脚本。不得在 Windows、生产路由器或局域网宿主直接运行 namespace、fixture 或产品采集命令。当前文件存在不代表实验已经运行；以精确源码、原始 run/job/attempt、工件和独立重放结果为准。

## 本轮预先冻结的退出条件

- 从 vendor、Go 1.23.12 编译现有 `cmd/server`，实际启动四个独立进程，而不是调用 `RunWith`、`httptest` 或替换 dial。
- 私有 mount/network/PID namespace 内只存在 loopback，无默认路由；`8.8.4.4/32` 只分配在该 namespace 的 loopback。它是**公网地址属性的隔离 fixture，不是真实公网来源**。只在该 namespace 放开非特权端口绑定；UID/GID 10001、capabilities=0、noNewPrivileges=1。
- 实际固定 IP DoT、正常 CA/SAN/SNI 的 HTTPS 443；不改系统根证书、宿主 sysctl 或时钟，不忽略 TLS 错误。
- `lab_contract.py` 在执行前冻结 46 次产品 API 调用及顺序：身份/范围/角色拒绝、来源创建与批准、两个来源抓取和本地接纳、历史回执、失败保留最后有效配置、进程重启、仅私有来源秘密版本变化使旧批准失效、独立写门锁定。
- 两个来源使用相同私有 YAML，公开节点身份必须仍按来源隔离；节点标签、错误和证据不得泄露 URL、令牌、原始节点名称、密码、私钥或私有库存。
- 负例包含无效 YAML、重定向、DNS 私网答案、不受信 CA、SAN 不匹配和超限正文。客户端按预算提前关闭超限正文时，fixture 必须如实记录实际发送字节/部分发送；不能把正常退出解释为正文完整传输或业务成功。
- 四个产品进程和来源 fixture 都必须正常 TERM/INT、实际 wait=0、join 并确认无残留。超时、紧急 kill、缺少状态或未执行都不得验收。
- 预先冻结 24 个 wire 测试（8 shape＋16 Linux 原生）与 24 个 runner、32 个 checker 合成辅助测试；辅助通过不能代替真实 46 调用。旧 Go 2620 ordinary/race 名单和旧浏览器门不替换、不缩减。

## 证据保管与独立判定

私有凭据、CA 私钥和库存仅存在于 namespace 的临时 tmpfs。公开实验目录精确 20 文件；其中源码前后清单由 CI 分别实际读取，包含全部 tracked `chengwang/**` 及本轮 workflow。主进程采集器不能自报 `PASS`，只允许输出 `CAPTURED/runtimeAcceptanceProven=false`。

独立 checker 不导入采集器或 fixture 的验证逻辑，检查原始 API 字节及 SHA、正常 TLS peer、公钥证书、wire 连接和请求边界、状态关系、外部审计链、源码原 Git blob 与进程退出。`private-readback.json` 只是可信采集器的安全投影，**不是独立验证原始私有数据库或系统级备份恢复**。build 报告绑定 CI 源码和实际二进制摘要，**不是独立可复现构建或恶意 CI root 的远程证明**。

成功的采集 job 后，再由另一个全新 Linux job 下载原公开工件，使用同一不可变源码完整重放 checker，并逐字比较报告。保留 Linux FD/path 元数据严格检查；Windows 的纯合成辅助检查不冒充 POSIX 文件保管或完整原 CLI 重放。

公开工件不包含原始服务 stderr、私有数据库、私有配置、秘密 SHA、凭据文件、HAR、trace 或浏览器 profile。安全失败仍保留可公开的原始材料，不补造缺失证据，也不取消运行中的旧验收。

## 仍不在本轮范围内

真实订阅资源页面尚未实现，当前双浏览器证明属于既有探针页面。按用户选择，后续资源页面须同时通过 Chrome/CDP 与固定版本 Playwright，不将一条路径替代另一条。

自动调度、完整内核配置和节点业务可用、断电恢复、容量/长期浸泡、系统级备份恢复、隔离设备发布/读回/回滚、企业正式 Registry/密钥及生产灰度仍未完成。整项 `subscription_orchestration` 仍为 `design_only`，授权保持 `BLOCKED`。

本轮不 SSH，不修改 OpenClash/爱快/DNS/Kuma/ERP，不合并 main，不发布正式镜像，不动生产。

## 提交前辅助结果（非原生验收）

单一集成者独立执行冻结的 runner 24＋checker 32，共 56 项纯合成辅助测试，最终均 run/pass 一次、0 skip。固定完整名字的 sorted-LF SHA256 分别为 `23574c38480dc9936345cc9de9950365b1b1be88298b5e8c76ef6cc13c8aa5bc` 与 `7f42b31818aafb4c0b77e7a47a16c0ae407547619aacdc070ca911e4608c477e`。wire 名单 24 项的固定指纹为 `c22d31e8501e9975760ef1d59dfbd4c7de1074107bb3ac42bcd27fbcd458f565`；Windows 仅 8 shape pass、16 Linux skip，不算 24 原生通过。

两次 Windows 辅助失败不覆盖：runner 原为 23 pass/1 error；之后 checker 原为 31 pass/1 error，均在正例文件的 FD/path 严格元数据比较处拒绝。改的是纯辅助正例的显式合成 POSIX 元数据，不删除测试、不 skip，也不放宽运行时完整 custody 比较；历史失败未留存完整三通道值，不能据此宣称唯一根因。真实 Linux 原件文件保管仍由 CI 完整执行。

## 首轮真实 CI：严格失败，不覆盖

源码 `2a689730cd7add43d7a15028cfd3c47d29754d06`，[run 39954809983](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39954809983)，producer job `120417876671`。24 wire＋24 runner＋32 checker 实际 run/pass、0 skip；实际产品完成 46 capture/4 epoch，但后续独立 checker 失败。fresh Linux replay job `120418257967` 跳过，不算通过。原 ZIP、日志、计数与边界见[机器记录](../../docs/evidence/p2-subscription-product-attempt-2a68973.json)。

原工件按原 Git checker 逐函数诊断首先拒绝 `wire-http-empty`：oversize 的 HTTP event 为 `partial/bytes=0`，API 为 503。该诊断使用未改动的原 20 文件语义，不冒充 Windows 完整 POSIX CLI 重放或 Linux 原异常栈。一次大块 `SSLSocket.send` 抛出时，已处理的部分不能从返回值精确恢复；0 仅指累计成功返回计数，不表示远端收到零字节。候选修正将 HTTP header 和有界 body 分开发送，只累加真实返回值，保留独立正字节门、响应原字节和所有原超时，不补造旧工件。
