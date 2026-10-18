# 10.88.0.254 部署记录

部署时间：2026-10-18（Asia/Shanghai）

## 当前状态

> 本节是最后一次生产读回的事实快照，不会随本地源码自动更新。当前生产是“默认锁定的 Shadow 操作控制面”：相关代码和页面已经部署，但身份文件未配置、操作写开关关闭、设备执行器不存在。它不接管生产流量，也不能执行设备变更。

- 访问地址：`http://10.88.0.254:7811/`
- 部署目录：`/opt/chengwang`
- 容器：`chengwang`
- 镜像：`chengwang:local`
- 镜像 ID：`sha256:0004384b7494d2beb1e76b56b8afe24d932592533fc26796b541e7314f59ddee`
- 运行模式：`shadow`
- 发布能力：锁定，接口返回 HTTP 423
- Shadow 操作身份：未配置，接口返回 HTTP 503 `operation_control_not_configured`
- Shadow 操作写入：`CHENGWANG_OPERATION_WRITES_ENABLED=false`
- 设备执行器：不存在，协议固定声明 `effect=local_record_only`、`deviceActionsExecuted=false`
- Mihomo 接入：本机 Controller API，只读；匿名端点只返回脱敏可达性和新鲜度
- 敏感诊断：`runtime`、`readback`、`versions`、`evidence/integrity` 均要求身份与管理范围；当前未配置身份，因此返回 HTTP 503
- 管理传输：局域网明文 HTTP 不发送或接受 Bearer；前端锁住令牌输入，服务端返回 HTTP 426
- 认证信息：仅保存在目标机 `/opt/chengwang/.env`，权限 `600`；未写入仓库或本记录。

## 备份位置

- 首次部署前证据：`/root/chengwang-backups/20261018-135915-predeploy`
- 演示数据边界修复前完整备份：`/root/chengwang-backups/20261018-140943-demo-boundary`
- 系统闭环页面发布前完整备份：`/root/chengwang-backups/20261018-143240-pre-system-readiness`
- 证据链运行时发布前完整备份：`/root/chengwang-backups/20261018-150218-pre-evidence-runtime`
- Shadow 操作控制面发布前完整备份：`/root/chengwang-backups/20261018-160829-pre-shadow-control`
- 安全加固版发布前完整备份：`/root/chengwang-backups/20261018-173811-pre-security-hardening`
- 当前版本的直接回滚镜像：`chengwang:rollback-20261018-173811`

备份目录权限为 `700`。发布前备份保留部署源码和受保护的 `.env`；对应回滚镜像使用独立标签保留。

## 验收结果

- 容器：`running / healthy`
- 容器用户：`chengwang`（非 root）
- 根文件系统：只读
- 持久化目录 `/app/data`：可写
- 健康接口：HTTP 200，`status=ok`、`mode=shadow`、`mihomoReadbackConfigured=true`
- Mihomo 匿名状态接口：HTTP 200，只含 `configured/reachable/fresh/stale/observedAt`，未返回版本、地址、节点、策略组或规则
- 敏感诊断接口：匿名访问 HTTP 503；当前生产不提供可复用管理令牌
- 局域网独立访问：首页 HTTP 200
- 局域网明文 Bearer 探针：HTTP 426；前端产物包含并显示明文管理入口锁定边界
- 容器最近 100 行日志：0 个 `panic/fatal/error`
- 发布接口：HTTP 423，保持锁定
- OpenClash：`running`
- 原 Home Assistant 容器：`running`
- 能力事实接口：HTTP 200，共 15 项；`real_authentication` 与 `durable_operation_control` 因生产未配置身份而显示 `blocked`
- 生产控制：`productionControlEnabled=false`，整体阶段：`foundation`
- “系统闭环”页面：局域网浏览器实测，能力证据与限制正常显示
- 匿名 Shadow 证明：HTTP 200，证据有效且时间新鲜，但不泄露精确事件数
- 完整证据校验接口：需受保护管理身份；当前匿名访问 HTTP 503
- 证据目录权限：目录 `0700`，日志与 checkpoint `0600`，UID/GID 10001
- 操作目录权限：目录 `0700`，快照与锁文件 `0600`，UID/GID 10001
- Shadow operations：无认证配置时 HTTP 503；响应明确为本地记录边界，不产生设备动作
- “操作中心”页面：局域网浏览器实测，清楚显示执行锁定、身份未配置和本地影子记录边界
- 独立只读验收器：对生产地址执行 5 项检查，健康、安全头、能力事实、operations 失败关闭和最小 Shadow 证明全部通过
- 容器重启：实际执行后恢复 `running / healthy`，证据完整性继续为 `valid=true`
- 单写者门禁：第二实例复用同一数据目录时启动被拒绝
- 回滚演练：旧镜像在独立端口实际启动，健康与 Mihomo 只读读回通过后才移除测试容器

全量 Controller `/proxies` 返回 108 个条目，其中包含普通节点；页面的 102 是具有成员列表的实际策略组数量，二者统计口径不同。

## 数据真实性修复

首次浏览器验收发现运行总览仍显示种子演示值。该版本没有把演示值冒充实际状态，但视觉上仍可能产生误解，因此未判定通过。

修复后总览明确标记为“演示总览”，隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等未接入数据；业务与 DNS 显示“未接入 / 未知”。真实 Mihomo 证据只在“设备读回”页面展示。

浏览器证据：`docs/design/deployment-10.88.0.254-readback-v1.png`。

## 2026-10-18 系统闭环事实页发布

新增 `GET /api/v1/capabilities` 和“系统闭环”页面。页面只显示控制面登记的事实能力，并把生产只读、本地实现、仅设计和受阻状态分开；不使用百分比或静态产品路线图冒充完成度。

本次完整 Docker 构建因 Docker Hub 连续返回 EOF 而未完成，现有生产容器未受影响。随后使用 `Dockerfile.offline`，基于已验证的回滚镜像，只替换本机交叉编译的 Linux/amd64 应用二进制和已通过构建的前端静态文件。候选镜像先在 `127.0.0.1:17811` 独立运行并通过健康、只读 Mihomo、非 root 和生产写入关闭检查，之后才切换正式容器。

第一次离线候选测试发现 Windows 产物没有 Linux 执行位，容器被运行时拒绝；该候选未进入生产。`Dockerfile.offline` 已加入显式 `chmod 0755 /app/chengwang`，重新构建的候选通过后才发布。

发布后证据：

- 容器 `running / healthy`，重启次数 0。
- 只读根文件系统、host 网络和 `no-new-privileges` 保持不变。
- 容器仍以 UID/GID 10001 运行。
- Mihomo 版本仍为 `alpha-smart-gdaf3ad0`，只读状态接口正常。
- 局域网 API 实测：13 项能力、生产只读 1、本地实现 5、仅设计 7、受阻 0。
- 浏览器请求 `/api/v1/snapshot` 与 `/api/v1/capabilities` 均为 HTTP 200，控制台 0 errors、0 warnings。
- 回滚镜像已在独立端口实际启动并通过健康检查，然后删除测试容器。

浏览器证据：`docs/design/system-readiness-production-10.88.0.254-v1.png`。

## 2026-10-18 证据链运行时发布

服务启动时会打开 `/app/data/evidence`；已有证据日志或 checkpoint 损坏时启动失败关闭。新增 `GET /api/v1/evidence/integrity`，只返回完整性报告，不返回事件正文。健康接口新增 `evidenceConfigured` 与 `evidenceIntegrity`。

候选镜像先在 `127.0.0.1:17811` 验证，并完成一次停止/重新启动；重开后 checkpoint 校验仍为 `valid=true`。正式发布后从独立局域网客户端验证健康、能力清单和完整性接口均为 HTTP 200，浏览器控制台 0 errors。旧镜像 `chengwang:rollback-20261018-150218` 也在独立端口实际启动通过后才清理测试容器。

该能力当前只证明本机哈希链与 checkpoint 可校验，不证明企业审计完成：事件数为 0，没有真实用户身份、全请求审计、WORM 或独立副本。

浏览器证据：`docs/design/system-readiness-evidence-production-v2.png`。

## 2026-10-18 默认锁定 Shadow 操作控制面发布

本次发布把以下源码装入生产镜像：静态 Bearer 摘要身份加载、默认拒绝授权、schema v2 操作库、强化证据链、pre/result 控制协调、受保护 operations API，以及“操作中心”页面。发布采用离线应用层更新，未升级旧镜像的基础系统层。

第一版候选验收发现一个 Go typed-nil 接口边界缺陷：未配置的 `*authn.Store` 被装入接口后被误判为已配置，导致候选返回 401 且能力状态错误。该候选没有进入生产。修复后新增回归测试，重新构建的候选才进入切换流程。

本次发布证据：

- 发布包：`chengwang-shadow-control-20261018-160829-v3.tar.gz`，SHA-256 `5b2539f5d4fcaa149a3dd0997f3abf3c48ce682aa93ae567aa319c3ce128c6ee`。
- Linux/amd64 应用二进制 SHA-256：`bde6f516644109408d674a9bb4c3c45399ee6f6f50a8870367062781803d2482`。
- 候选验证了身份未配置时失败关闭、能力状态、健康、Mihomo 只读、证据完整性、非 root/只读根文件系统以及无设备执行。
- 正式切换后读取到本文顶部所列镜像 ID；容器重启、单写者拒绝和旧镜像独立启动均通过。
- 浏览器实测“操作中心”并确认控制台 0 errors、0 warnings；证据图为 `docs/design/operation-center-production-shadow-v1.png`。

生产刻意没有身份文件，写开关保持 `false`，设备执行器仍不存在。因此已部署的是失败关闭的控制面骨架，不是可写生产控制，也不能宣称闭环完成或 `99.999999%` 可用率。

本次发布之后新增到工作区的 `cmd/verify-shadow` 和 signal-aware 优雅关停源码尚未进入本文顶部所列生产镜像。只读验收器已经从开发机验证当前生产；优雅关停仍须在下一候选镜像和正式容器中复验后，才能记为生产能力。

## 2026-10-18 安全加固与最小公开证明发布

本次发布修复了安全扫描确认的 5 类中风险边界，并收口独立绕过审查发现的回归：完整运行态、版本库和证据全量校验改为受身份与资源范围保护；匿名接口只保留最小健康/Shadow 证明；浏览器在局域网明文 HTTP 上不会发送 Bearer，服务端也返回 HTTP 426；Mihomo 刷新增加短缓存、单航班和等待者上限，令牌仅可发往回环 HTTP 或明确白名单内的远程 HTTPS 主机，且不继承环境代理；Evidence 健康状态改为常量时间缓存；版本目录改为分批枚举并在发布前执行硬配额。

可追溯产物：

- 发布包：`chengwang-security-20261018-173728.tar.gz`，SHA-256 `c6a5d09e153f7cf3c6f967581523c6e35b7b3db163826f4ac41c79131be7dc01`。
- Linux/amd64 服务二进制 SHA-256：`7a19f647719b53f4daaa9cc884a0adf8f4bc0444d44c032bba020fca828e7861`。
- Linux/amd64 独立验收器 SHA-256：`5d1ca16f365c2226f7b90277f98b45048457d31672e4dfccd158c4566deb7693`。
- 最终源码与部署记录证据包：备份目录内 `source-final.tar.gz`，SHA-256 `759dd4d43aa786732f2acc3a8f9aa55ca06c7c884011198d48cb7d7db00acd9d`。
- 候选镜像与正式镜像 ID：`sha256:0004384b7494d2beb1e76b56b8afe24d932592533fc26796b541e7314f59ddee`。

源码门禁实际通过：全量 Go 测试、`go vet`、关键安全包 race、Linux/amd64 交叉编译、前端 18 项测试、ESLint、生产构建和 Markdown 本地链接检查。远端 Compose 解析通过。候选容器使用备份数据副本，在 `127.0.0.1:17811` 完成 5/5 验收、匿名敏感端点失败关闭、发布锁、单写者拒绝、SIGTERM 优雅退出、重启持久性和局域网 HTTP 426 测试后才切换正式服务。

正式切换后 5/5 验收通过，容器保持非 root、只读根文件系统、host 网络、`no-new-privileges`、重启次数 0。正式容器执行 `docker stop -t 20` 时日志记录收到 SIGTERM 和 `chengwang shutdown complete`，重启后再次 5/5 通过；T+60 秒与 T+300 秒稳定观察仍为 5/5，重启次数保持 0，日志没有 panic/fatal/error。旧镜像使用备份数据副本在独立端口通过健康与 Mihomo 只读烟测。OpenClash 活动配置 SHA-256 保持 `4c969773cb85fc59fe7ef8d43246b222ca93249bb2d255669a2d48ec6f60a5a4`，Home Assistant 容器 ID 和运行状态保持不变。

当前仍刻意不配置身份文件，不启用本地操作写入，也没有设备执行器。本次是已部署的只读安全闭环，不是生产网络写入、自动修复或企业高可用闭环。

## 当前版本的备份/恢复注意事项

- Evidence 和 operation 各有进程生命周期单写者锁。同一数据目录只能由一个控制器打开；Store 提供幂等 `Close()`，进程退出也会由操作系统释放内核锁。当前服务入口尚未接入 SIGTERM 优雅关停，不能把容器停止记录成已调用应用层 `Close()`。
- 一致性备份应在容器停止后复制整个 `/opt/chengwang/data`，不能只复制 `operations.json`、`events.jsonl` 或 checkpoint 中的单个文件。
- 身份文件和 `.env` 属于秘密材料，目录保持 `0700`、文件保持 `0600`，不得进入 Git 或验收截图。
- `commit_unknown`、store poison 或 `checkpoint_stale` 发生时保持失败关闭，先保全整个数据目录再人工分析。当前没有经过验收的自动修复；不得删除锁文件、手改 checkpoint 或盲目重放写请求。
- 本机哈希链没有密钥签名，不是 WORM，也没有独立故障域副本；主机管理员仍可以替换整套本地证据文件。

## 快速停止

只停止澄网，不影响 OpenClash 或其他容器：

```sh
cd /opt/chengwang
docker compose down
```

## 回滚到 Shadow 操作控制面发布前版本

```sh
cd /opt/chengwang
docker compose down
cp -a /root/chengwang-backups/20261018-160829-pre-shadow-control/source/. /opt/chengwang/
docker tag chengwang:rollback-20261018-160829 chengwang:local
docker compose up -d --no-build
```

回滚后必须重新检查容器健康、证据完整性、Mihomo 状态接口以及 OpenClash/Home Assistant 状态。该回滚会移除新版 operations API/UI，但不会修改 OpenClash 配置。

## 回滚到证据链运行时发布前版本

```sh
cd /opt/chengwang
docker compose down
cp -a /root/chengwang-backups/20261018-150218-pre-evidence-runtime/source/. /opt/chengwang/
docker tag chengwang:rollback-20261018-150218 chengwang:local
docker compose up -d --no-build
```

回滚后必须重新检查容器健康、健康接口、Mihomo 状态接口以及 OpenClash/Home Assistant 状态。

## 回滚到系统闭环页面发布前版本

```sh
cd /opt/chengwang
docker compose down
cp -a /root/chengwang-backups/20261018-143240-pre-system-readiness/source/. /opt/chengwang/
docker tag chengwang:rollback-20261018-143240 chengwang:local
docker compose up -d --no-build
```

回滚后必须重新检查容器健康、健康接口、Mihomo 状态接口以及 OpenClash/Home Assistant 状态。

## 回滚到演示数据边界修复前版本

```sh
cd /opt/chengwang
docker compose down
tar -xzf /root/chengwang-backups/20261018-140943-demo-boundary/source.tar.gz -C /opt/chengwang
cp /root/chengwang-backups/20261018-140943-demo-boundary/.env /opt/chengwang/.env
chmod 600 /opt/chengwang/.env
docker tag chengwang:rollback-20261018-140943 chengwang:local
docker compose up -d --no-build
```

回滚后必须重新检查容器健康、健康接口、Mihomo 状态接口以及 OpenClash/Home Assistant 状态。

## 恢复到未部署状态

首次部署前不存在澄网容器和 `/opt/chengwang`。如需恢复到部署前运行状态，只执行：

```sh
cd /opt/chengwang
docker compose down
```

这会移除澄网容器和 Compose 创建的运行对象，不会删除 `/opt/chengwang/data`、备份或镜像，也不会操作其他容器。
