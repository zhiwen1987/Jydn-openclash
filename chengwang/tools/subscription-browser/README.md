# 订阅页面 DOM 观察增量（不是 E2E 验收）

状态：**仅实现并执行纯 Node 合成检查；真实浏览器尚未执行**。本目录不是完整浏览器驱动、独立工件 verifier 或正常 TLS 实验。没有修改旧 probe driver、旧门、产品依赖或生产环境。

对应计划：[真实订阅 UI 双浏览器验收](../../docs/P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)。真实目标仍为实际编译页面 → “订阅与提供者”导航 → 真实 `cmd/server` → 实际服务端权限/库存/回执。这里不将 fake DOM、`vm`、按钮状态或本地 JSON 视为这些目标已通过。

## 固定接口

`collect-subscription-dom.mjs` 不导入依赖。

- `collectSubscriptionDOM()`：无参数、自包含、只读 DOM 投影。没有 fetch、时钟替换、React 内部读取、表单写入或测试状态注入。
- `SUBSCRIPTION_DOM_EXPRESSION`：由同一函数源码生成 `(<function>)()`，仅把 CRLF 规范为 LF。后续 CDP `Runtime.evaluate` 与 Playwright evaluate 必须实际执行这同一表达式，不能给任意脚本回调权限，也不能扩大旧 probe 闭集。
- `validateSubscriptionDOM(value)`：检查闭集 schema，返回原对象；额外字段、unsafe integer、重复 ID、非法状态、错误四参数绑定与控件顺序均拒绝。它不是服务端 DTO、RBAC 或因果 checker。
- `assertNoPublicCanaries(value, privateCanaries)`：先校验 schema，再扫描其 JSON 投影。调用者在私有内存持有实际 canary 及应检查的编码变体；不记录 canary，也不导出它们。空 canary 集合拒绝。

后续 wrapper 必须先校验并完成 canary 扫描，才允许输出 snapshot。原始异常不导出；本模块自有拒绝消息固定为 `subscription DOM rejected`。不拦截真实浏览器异常来当成功。

## 公开投影闭集

schema：`chengwang.subscription-browser-dom/v1`。

| 类别 | 只观察的字段 | 不证明的内容 |
| --- | --- | --- |
| 页面/布局 | mounted 与 visible 区别；HTTPS 布尔；实际 width/height/scroll/clientWidth/scrollWidth；固定按钮 presence、enabled、矩形、中心 inViewport/hit-test | 布局通过、全区域可访问、实际点击成功或服务端接受 |
| 会话 | token/file input 存在、密码类型与空/非空；storage/cookie 空布尔 | 任意秘密在全 DOM/图片中不存在、服务端动作已撤销 |
| 资源 | 安全 source/candidate/node ID，当前显示 revision/baseRevision/state/format，节点固定 unknown | API 资源正确、能力可用、真实分页或健康 |
| 目录/批准 | 下拉安全 referenceId/revision/selected；本会话可见批准安全 ID/referenceId/policyRevision；session/handoff 模式独立 | 下拉引用就是交接的真实引用、跨 owner 回执权限已开放 |
| 交接 | 有效形态批准 ID/安全整数策略版本或 `null`，明确未读回引用提示布尔 | 任意填写交接已由服务端核验 |
| 确认 | 闭集 kind；fetch 必须提取 sourceId、expectedRevision、approvalId、policyRevision 四参数，缺失、重复、歧义或错误解释均拒绝；回退额外勾选状态 | 请求确实发出、四参数与后端回执匹配或设备回滚 |
| 回执/分页 | 真实可见回执安全命令 ID/版本/展示状态/历史重放/审计；候选/节点页码与版本；stale/alert/boundary visible | 网络采样、不可变存储、来源因果或审计链正确 |

无任意来源 label、原文、文件名、任意错误文本、URL、title、token 值、storage 内容、cookie 内容、HTML 或 React 状态导出。安全 ID/referenceId 仍可能碰上私有 canary，因此必须执行私有 canary 检查。`结果待核对` 只投影为 `pending`：页面同一文案无法区分 prepared/unknown，不能臆造其中一种。

控件固定顺序：connect、clear、refresh_sources、prepare_create、refresh_source、prepare_import、prepare_approve、prepare_fetch、prepare_admit、prepare_reject、prepare_rollback、confirm、cancel、candidate_previous、candidate_next、node_previous、node_next、read_receipt。未渲染控件保留 absent 分支。隐藏挂载不等于 unmount；不会把导航隐藏说成 token 被销毁。

## 本机执行的合成检查

Browser plugin not available；本机任务禁止实际 browser、Go、Vitest、Docker 和网络。因此这里只使用 Node 标准库、`node:vm` 和手工 fake DOM 接口，不安装依赖、不启动服务。fake DOM 不声称具有浏览器布局、CSS、原生控件或实际 React 生命周期语义。签出 fixture 对照真实 JSX 仍渲染两枚 radio，默认 `session`，不是 `absent`；`absent` 只在未挂载分支验证。祖先 hidden 通过手工 parent 链模拟 `getClientRects()` 为空，仅检验投影分支；这不是实际浏览器布局证据，也不证明隐藏挂载销毁了内存会话。

执行：`node --test chengwang/tools/subscription-browser/test-collect-subscription-dom.mjs`。

冻结 **36** 个 exact 测试名；按 ASCII 排序后以 LF 连接、**无尾 LF** 的 SHA-256：`ad5fe9a1b5cc63e0cf38e50d537d815369313041347cb721eca5327cc3b61f82`。新增订阅观察测试不能代替旧测试，也不构成扩大旧 allowlist 的授权。

```text
subscription DOM canary scanner rejects missing unbounded and empty canaries
subscription DOM captures all four immutable fetch confirmation parameters
subscription DOM directory rejects private URLs duplicated references and unsafe revisions
subscription DOM distinguishes hidden mounted navigation from destroyed session
subscription DOM expression is byte-identical self-contained code for both engines
subscription DOM extractor is readonly and avoids raw content state and network APIs
subscription DOM hit test records occluded and unobstructed controls independently
subscription DOM keeps verified session and unverified handoff explanations separate
subscription DOM module introduces no dependency or existing probe-driver coupling
subscription DOM never exports token file cookie or storage contents
subscription DOM observes a mounted signed-out page without invented inventory
subscription DOM observes safe node summary as unknown not healthy
subscription DOM private canary scanner rejects valid-shaped secrets too
subscription DOM projects current candidate IDs states and base revision
subscription DOM projects safe source IDs and revision but no arbitrary source label
subscription DOM projects valid handoff ID and independently entered policy revision
subscription DOM reads actual immutable receipt display without manufacturing kind
subscription DOM records horizontal overflow without declaring layout accepted
subscription DOM records real paging revision without inferring backend membership
subscription DOM rejects duplicate fixed controls instead of choosing first match
subscription DOM rejects missing duplicated or ambiguous fetch confirmation parameters
subscription DOM rejects prototype-key confirmation labels without echoing text
subscription DOM rejects rendered healthy node claims and private node labels
subscription DOM reports actual desktop and 375-width mobile geometry
subscription DOM reports invalid handoff fields without exporting arbitrary input
subscription DOM represents a genuinely unmounted page with absent controls
subscription DOM requires the extra rollback checkbox and observes its checked state
subscription DOM resource bounds reject oversized pages and unsafe candidate counts
subscription DOM retains pending receipt ambiguity instead of inventing unknown outcome
subscription DOM schema rejects duplicate source candidate and node identities
subscription DOM schema rejects extra fields at every populated boundary
subscription DOM schema rejects malformed identifiers without leaking their value
subscription DOM schema rejects multiple selected resources and known-health nodes
subscription DOM schema rejects unsafe integers fractional values and wrong types
subscription DOM schema requires frozen control order and closed semantic states
subscription DOM separates directory choice from session approval and handoff binding
```

当前 LF 表达式：11926 bytes，SHA-256 `41679f346d4d6fcfa1fd393083583855b659991741579d73950d787e6bf5e429`。该值用于整合时绑定本轮表达式，不是供应链认证；任何修改需先更新契约、合成反例及源码绑定，不能用新 hash 自动替换失败证据。候选 stale 查询限定候选 panel 的直接 `p.subscription-stale`，不会把嵌套节点 stale 误记为候选 stale；已有分页测试名内包含这个层级反例。

## 明确还缺少

1. 新订阅专属安全启动/关闭 wrapper、network journal、正常短期 TLS/NSS、隔离 namespace 和真实 `cmd/server`/wire fixture。
2. B01–B23 的固定 flow/dataset/步骤/角色/capture 合同、真实 file input/POST/批准交接/回退/分页/异常恢复的双引擎操作。
3. 实际 API 原字节、源码/构建/进程/CA/TLS/审计/Store 安全投影之间的关联。
4. 新独立 checker、负面工件、精确文件闭集、producer 与 fresh Linux 重放报告相等证明。
5. 两条 engine 各自真实桌面与 375 viewport 截图、人工看图、控件交互和 console/runtime 检查。
6. 现有旧探针 CDP 取消失败的独立原因和修复证据。本目录不绕过、吞掉或重新解释该失败。

这些未完成项没有被 collector 或 36 个合成检查补证；此目录不能把订阅 UI 标成真实 E2E 已验收。
