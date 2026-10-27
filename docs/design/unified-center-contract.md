# 进源Clash Center：统一入口与验收契约

## 方向

服务现有局域网管理者，解决地址分散、同步含义不清、异常难定位和操作结果难确认的问题。目标是让日常查看、定位、操作和核验在同一个地址中完成，降低误操作和维护成本。产品采用清楚、克制、可信的浅色后台：白色表面、冷灰画布、蓝色主色，状态同时使用图标与文字。优先呈现整体运行、真实业务走向、分阶段同步、待处理事项及操作结果。保留完整模块和高级管理，按任务逐步展开；移动端同样可以查看与操作。所有运行状态来自真实接口，未连接和过期都明确显示，不生成假成功率或假进度。

用户提供的 Logo 原文件放在 `monitoring/lan-center/unified-center/assets/logo.png`，品牌文字为“进源Clash Center”。仅复用原文件，不改图案。视觉参考图位于本机生成目录，属设计示意，示意数字不进入运行默认数据。

## 模块与路径

统一主入口为原订阅管理地址的 `/`，内部导航用 `#/overview`、`#/routing`、`#/nodes`、`#/subscriptions`、`#/dns`、`#/monitors`、`#/backups`、`#/activity`。静态资源统一 `/center-assets/`。原 provider 路径、Token 和允许来源不变。保留原有本地节点管理 API；原管理页面可在同源 `/classic/subscriptions` 打开。Kuma 高级管理和 LuCI 高级管理通过固定目标同源代理接入，不提供任意 URL 代理，也不绕过各自认证。

## 前后端接口

`GET /api/center/overview` 返回下列结构，字段无证据时为 null/unknown，单部分失败不使其他部分消失：

```json
{"schema":1,"updated_at":0,"overall":{"state":"unknown","title":"等待检测","detail":""},"metrics":{"nodes":null,"subscriptions":null,"selectors":null,"rules":null},"sync":{"state":"unknown","stages":[],"information_sources":null,"node_sources":null},"services":[],"businesses":[],"nodes":[],"subscriptions":{"providers":[],"source_sync":{}},"dns":{"state":"unknown","upstreams":[],"detail":""},"monitors":[],"backups":[],"events":[],"issues":[],"capabilities":{"writes":true,"advanced_monitor_path":"/dashboard","advanced_router_path":"/cgi-bin/luci/"}}
```

通用状态为 `ok / running / pending / warning / error / stale / unknown`，前端均译成中文。`sync.stages` 每项有 `id,label,state,detail,last_success,next_due`；区分信息来源读取、节点检测、受控发布和运行加载，明确“信息来源 N 家”不等于“已发布 N 家节点”。加载验证只报告已取得的证据，例如节点名/数量一致，不冒充端点和业务全部通过。

`businesses` 每项含 `id,name,selection,leaf,chain,options,state,detail`；`id` 为真实策略名。`services` 每项含 `id,name,state,checked_at,detail`。`issues` 每项含 `id,title,detail,page,state`，`page` 为上述模块键。`events` 每项含 `at,title,detail,state`，无真实时间则不伪造。

`GET /api/center/session` 返回 `{authenticated:false}` 或 `{authenticated:true,csrf:"..."}`，不返回管理密钥。登录和退出沿用 `/api/local/login`、`/api/local/logout`，Cookie 路径支持 `/api`。

需登录、同源和 CSRF 的操作：

- `POST /api/center/select`：`{group,choice,expected}`，先核对当前值仍等于 expected，验证 choice 为实际成员；只能选择，不修改组定义。冲突返回 409。
- `POST /api/center/node-test`：`{provider,name}`，只测真实 provider 节点，不切换任何组；返回真实毫秒值和结果。
- `POST /api/center/backup`：`{}`，创建中心数据/配置备份任务，返回 `202 {job_id,state}`；不创建路由器备份，不暗示整机灾备。
- `GET /api/center/jobs/<id>`：任务状态与阶段；完成后才给出下载地址。
- `GET /api/center/backups/<id>/download`：需有效管理会话，备份含敏感信息，不能匿名下载。

原 `/api/local/status / preview / publish` 继续服务自建节点管理，不用新代码绕过既有解析、发布或校验。页面中的刷新只更新观测数据，不触发节点发布或清空 DNS。

## 实施边界

已有后端为 Python 原生 HTTP 与无构建依赖的 HTML/JS，本次延续此架构，静态资源随镜像发布，不依赖外部 CDN。保留现有认证和真实接口；不在前端或镜像写入生产密码、Token、节点密钥。新的统一入口通过环境开关启用，关闭后可恢复原页面。

隔离测试不得修改生产 DNS、业务选择、节点拉取地址或生产数据。生产上线由主代理统一执行，必须备份、独立回退守卫、比较运行基线。新镜像先在独立数据副本和测试端口验收，确认后再安排生产切换。
