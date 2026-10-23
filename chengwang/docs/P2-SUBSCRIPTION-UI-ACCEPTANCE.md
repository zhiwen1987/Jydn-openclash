# P2-06a 订阅页实现与隔离回归记录

更新：2026-10-23。源码 `8f610a4e946ef23b6ccaeafeef3f3cdfbc0591e3`，开发分支 `codex/chengwang-security-hardening`。**本轮整体未验收通过，未上线。** 当前明确阻断为旧探针 Chrome/CDP 回归的一个取消请求；新订阅页本身的真实双浏览器实验仍待实现。

## 实际实现

1. 原“订阅与提供者”占位接为真实本地准入页面：来源、候选/节点分页、创建、文件导入、批准、Fetch、接纳/拒绝、本地回退和命令回执。节点仍 unknown；不执行设备发布、测速或代理业务连接。
2. 两个安全 access GET 提供范围、角色动作、两层写门交集及最多32个安全策略引用，不改旧必需 Backend 接口；不输出 URL/CA/凭据，不替代每个写请求的鉴权。
3. 同源 HTTPS、流和严格 JSON/DTO 预算、30秒硬期限、内存会话与私有导入 intent、一次显式提交、未知结果只读查证、来源/修订/会话迟到结果围栏。
4. 抓取明确分“本会话已读回批准”和“交接批准ID（未核验）”；交接版本独立输入，确认展示实际四个请求参数，并说明目录下拉不绑定交接实际引用。不放宽跨 owner 回执读取权限。

这些属于已实现候选，不是已经验证全部真实操作闭环。跨角色批准安全上下文的自动读回、任意 URL/私有目录编辑、调度、完整内核、设备运行发布及整套恢复仍未完成。

## 本轮实际证据

| 范围 | 实际结果 | 不能据此证明 |
| --- | --- | --- |
| [父门39966375644](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39966375644) | ordinary/race 各2644 Test run/pass、每对一次、0 Test skip/fail；Fuzz函数及seed项每轮12另计，domain无测试的package skip另列；五份精确Git脚本独立/根会话重放通过，旧2620/130/87及更早名单保持 | 新 access API 的真实浏览器/TLS链路；实际业务可用率 |
| [前端/镜像39966375721](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39966375721) | CI终态success；前端9文件190项全过、0失败/skip/todo，旧117及新增40/32/App1精确名单保留；lint/build成功。子模块ordinary/race各732、Registry三名及旧名单通过；根会话核对原ZIP/五份JSON，重放精确Git前端inline、Go及Registry门通过，97/763原始源码blob绑定保持 | 新页真实渲染/E2E；旧7个产品CLI仅CI通过及来源绑定，未逐个独立重放 |
| [订阅独立后端39966375738](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39966375738) | 80具名辅助、46 API、4进程代次、26连接/102事件；producer与fresh Linux完整原门均成功；根会话以原ZIP20文件映射重放语义，与两Linux原报告2496B逐字相同 | Windows完整POSIX custody、私库原始独立验证、公网或新页面E2E |
| [旧探针双浏览器39966375625](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39966375625) | PW backend22/browser原门均重放通过、报告逐字相同；CDP backend22通过，但browser原门因failedRequests=1拒绝，其他7计数0。正常退出不抵销失败 | 旧CDP通过、取消已解决、新订阅页面浏览器已通过 |
| 新订阅页面实际渲染 | 未执行。没有新页PNG、桌面/375移动端、遮挡、键盘与真实交互验收结果 | 不写“视觉P0为0”、不借旧探针截图、不以jsdom替代浏览器 |
| 生产 / main / 正式镜像 | 未修改 / 未合并 / 未发布 | 未声称上线、灰度完成或全系统闭环 |

完整摘要、原始 run/job/artifact ID、大小和 SHA 见[本轮机器记录](evidence/p2-subscription-ui-8f610a4.json)。原始ZIP/日志在平台及本机私有临时证据目录；平台保留期不是永久WORM归档。所有重放均用精确源码 blob，不从绿灯输出重新冻结名单。

## 修正与失败历史

- `9c622a2`：前端190实际172通过/18失败（client17、App1），旧117和组件32通过。跨运行域正常字节被 `instanceof` 误拒。该失败及首轮CDP失败见[原记录](evidence/p2-subscription-ui-attempt-9c622a2.json)，未覆盖。
- `9a0f962`：以原生 typed-array 品牌 getter + `ArrayBuffer.isView` 修正，不用可伪造 tag/duck typing；40名不变。实际190/190、父门各2644、旧双浏览器原门及订阅后端通过。镜像CI成功，前端/子模块732/原Registry三门已独立重放，旧7个产品CLI仅实际CI成功与来源核对，未逐个独立重放。不能将其一次CDP绿灯说成取消原因已经修好。
- `8f610a4`：补交接双模式与明确参数，原32名不变；新CI独立运行。CDP同类取消重现，所以本轮继续拒绝验收，不通过重试或忽略计数凑绿灯。

## 当前CDP阻断：已知与未知

已确定的只是：`Network.loadingFailed` 对一条 probe status 请求报告 canceled/aborted；此前见到2xx响应头，网络事件年龄落在小于1秒桶。协议的 canceled 标志不包含唯一调用方原因，2xx头也不证明body完整。[CDP官方事件定义](https://chromedevtools.github.io/devtools-protocol/tot/Network/#event-loadingFailed)

本轮CDP/PW实际 served 的10个Web文件逐字相同。实际React renderer `bundleType:0`、版本 `19.3.1`，属于生产构建；虽然页面有 StrictMode 壳，不能认定发生开发构建才有的额外effect重跑。[React官方说明](https://react.dev/reference/react/StrictMode)

源码中摘要 controller 的显式abort入口只有10秒deadline和effect cleanup；token修改/清除操作取消的是明细controller。现有单飞分支不会因重叠的摘要点击直接取消旧摘要。原记录仅一条document响应，流程只有一次导航及一次进入代理节点；未证明额外remount，但也没有生命周期日志证明绝无remount。

`AGE_LT1S` 起点是 CDP requestWillBeSent，不是 JS 定时器arm；wrapper最终输出标志的时间也不是取消发生时刻。因此既不能称10秒超时已证实，也不能绝对排除deadline。成功EOF后cancel的纯Node语义不是Chrome运行因果证明；不得据此盲修读取器。

下一项先冻结最小闭集观测：同一请求关联 JS arm/fire/cleanup/stream-cancel入口、组件/请求所有权、CDP开始/失败、文档/加载器变化和实际事件时钟；仅导出固定枚举、计数/时间与安全ID，不导出令牌、原文、URL或原始错误。诊断候选必须继续保留原门、原失败和总预算，先拿可区分证据，再选择修复。之后才按[计划](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)实现新订阅页两条真实浏览器路径；两条都需要，不能用本轮旧页回归替代。
