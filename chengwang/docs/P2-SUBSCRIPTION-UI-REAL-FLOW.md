# P2-06b：真实订阅页面接线与验收进度

本记录是产品浏览器验收的当前增量，不取代 [B01–B23 完整合同](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)。不变更生产、不发布镜像、不合并 main，不解除 `authorization=BLOCKED`。

源码 `aedd1946b3dd15290fd6b2675c7eeb0b8593509c` 的首次原运行 [39998551196](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39998551196) 四个作业已全部成功；两个引擎的完整原 checker CLI 已在主代理和独立子代理实际重放，均与 producer / fresh Linux 报告逐字一致。[机器证据](evidence/p2-subscription-ui-real-flow-aedd194.json)保留具体 job、工件摘要、重放与缺口。**仅创建/回执流程隔离验收通过，完整 P2-06b 尚未完成。**

## 当前交付

单一集成者合并三个隔离实现面：真实页面驱动、真实产品运行器、独立原件检查器。新入口为 `.github/workflows/chengwang-subscription-ui-browser.yml`，固定 Chrome 候选及 Playwright alpha 的依赖锁来自已审原件，不替换历史 pin 文件或旧产品门。

目标流程：实际编译 Web / 实际 `cmd/server` → 匿名页 → Operator 连接 → 准备/取消（无写入）→ 再准备 → 唯一创建 → 桌面/移动原始截图 → GET 耐久回执 → 隐藏导航 → 返回 → 清会话。两个引擎都必须执行，不能以一条成功抵销另一条失败。

| 项目 | 当前证据 | 不能据此宣称 |
| --- | --- | --- |
| 三实现面与固定合同 | 新增于独立目录；未修改生产规则、产品 UI 或 Go 实现 | 整个产品或生产已完成 |
| 合成反例 | 集成者实际执行 Node 32 / Python runner 16 / checker 36，共 84 项，零跳过；实际原事件名单摘要固定，另有 AST 名单对照 | 84 项等于业务可用率或真实页面验收 |
| 静态语法 | 六 Python AST、四 Node 语法及八 workflow Bash 块通过 | 构建、浏览器或 Linux 隔离已通过 |
| 真正编译与运行 | 两 Linux producer 实际编译同源码 cmd/server 与 10 文件 dist；实际 Chrome 157.0.8103.6/revision `41520584daa68d0040db7746ae562a0ff82187f6`，ELF 与审定 pin 一致；每引擎 14 请求/11 DOM/2 PNG | 已验全部订阅业务、真实公网或节点可用性 |
| 独立验收 | 每引擎 14 公开原件、846 Git blob、唯一 POST/GET 回执、一条含两个事件的外部审计链、安全投影与三进程正常 wait=0，八计数全 0；两 fresh Linux、根/独立子代理完整 CLI 通过，四方报告逐字相等 | 安全投影等于独立读取原私有数据库，或摘要等于可复现构建证明 |
| 视觉验收 | 主代理实际查看两引擎的 1440×900 与 375×900 原 PNG；身份、非空、无框架覆盖层、首屏可读和无横向溢出已查，滚动位置均 0 | 首屏截图等于折叠以下全部控件/候选/节点/错误态已视觉验收 |

实际交互由真实 PW locator 或 CDP Input 完成，不注入 fetch、React 状态或 mock API。准备与取消没有 POST；确认只产生一条创建命令，实际 source revision=1、库存列表/候选空页/回执一致。隐藏导航保留实际 DOM，不冒充组件卸载；清会话后来源与回执清空，密码/文件输入和存储仅输出空值断言。

根和独立子代理另复核同源码父门 [39998551042](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39998551042)：七份原 Git checker、HTTP 原日志 6069650B，ordinary/race 各 2644 Test 恰一次 run/pass，零 skip/fail，各 12 Fuzz 另计。旧订阅 [39998551197](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39998551197) 两 Linux 完整门成功；根/代理原字节语义重放通过（20 原件、46 API、4 epochs、26 wire connections、102 events、835 Git blobs），报告逐字等 producer/fresh。Windows 完整 POSIX CLI 仍原样拒绝 `public-file-open-race`；此处适配仅替换文件读取，**不是本机完整 POSIX CLI 通过**。

四份 UI 原小包共 54 文件、两份旧订阅小包共 26 文件，下载原 ZIP 摘要与 GitHub artifact digest 及逐文件内容均核等；未下载浏览器 ZIP/ELF 到本机。临时主代理证据根：`C:/Users/Administrator/AppData/Local/Temp/chengwang-subscription-ui-aedd194-root-849ec0cd08264eb9a3d0f8e7805adfa8`。原工件仅保留 14 天，临时目录不是永久集中归档。

首次运行失败必须保存原失败及诊断，禁止通过重跑挑选绿色。若需修复，另作源提交产生新的原始运行；不能回填原运行缺失证据。CI 仅上传有界公开结构化原件和截图，不上传 ELF、浏览器 ZIP、私钥、令牌或 profile。

## 信任和安全边界

- 构建只在隔离 Linux CI 的只读源码、无默认路由环境执行，Go 使用 vendor，不下载 Go 依赖；依赖获取与运行分阶段。
- 实际页面使用正常私有 NSS 信任和 TLS 校验，不用 `ignoreHTTPSErrors` 或证书绕过。进程 UID 10001、空 capabilities、no-new-privileges，网络只有 loopback。
- 授权头原值不导出；实际私有 canary 及编码/摘要变体在公开前扫描，响应 base64 要先独立解码再扫描。编译 JS 的合法 `Bearer ` 代码字面量不是令牌本身。
- `/api/v1/snapshot` 是页面启动的独立真实请求，包含实际浮点指标；不得拿它混作订阅 DTO 或篡改订阅整数校验来通过。
- 本流程不配置抓取策略，不发订阅网络抓取，不做 DNS/节点/内核/运行发布。正常创建、耐久命令回执、审计链和安全投影才是此增量的验收目标。

## 保留的未完成项

按原 B01–B23 合同逐项对账：B01 的匿名入口已覆盖；B02/B04/B05/B06/B20/B21/B22/B23 仅覆盖上述子集；B03/B07/B08/B09/B10/B11/B12/B13/B14/B15/B16/B17/B18/B19 未覆盖。1 项完整路径、8 项部分、14 项未覆盖是范围分类，不是整个系统完成百分比；无 wire 的三进程关闭不能补证完整抓取链生命周期。

完整 B01–B23 的所有角色、跨范围隔离、导入、来源批准、抓取、接纳/回退、分页、重启及失败恢复仍需按原合同逐项实现/验收。候选的旧探针/旧产品完整回归、镜像门、备份恢复、单目标隔离发布及业务读回不能被本流程替代。灰度、生产和运营观察仍未执行。

下一实现片段：在独立冻结实验中完成双来源真实私有文件输入、来源隔离与安全节点读回、Viewer/Auditor/Operator/Approver 的实际权限、接纳/拒绝及按当前 revision 的明确回退；之后补来源批准/交接/DoT 抓取、分页及失败/重启矩阵。不扩大旧实验闭集、不用创建成功代替这些需求。
