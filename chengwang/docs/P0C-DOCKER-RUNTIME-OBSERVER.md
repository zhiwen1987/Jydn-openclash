# P0-c Docker 运行态观察器

## 结论边界

P0-c 只形成一条 **本机、只读代理、诊断级** 的 Docker 运行态观察链。即使全部门禁通过，结论也只能是：

```text
schema        = chengwang.restore-docker-runtime-observation/v1
boundary      = ADVISORY_LOCAL_DOCKER_RUNTIME_BOUND
authorization = BLOCKED
blockers      = 9 项全部保留
```

它不是镜像供应链证明、独立 attestation、可信 current-state、恢复授权、生产部署或业务可用性证明。

## 为什么不能让观察器直连 Docker

Docker 主 socket 通常等价于宿主 root 写能力。即使当前代码只发送 `GET`，把主 socket 交给观察进程仍会扩大为容器创建、宿主挂载和特权执行入口。因此实现拆成两个不同权限域：

```text
restorecurrent.OpenReleaseBound handle
        │
        ▼
restoreruntime.Capture（无权访问 Docker 主 socket）
        │ 固定 Unix socket：/run/chengwang-runtime-observer/readonly.sock
        ▼
docker-runtime-readonly-proxy（特权 TCB）
        │ 仅固定 Docker Engine GET
        ▼
/run/docker.sock
```

`docker-runtime-readonly-proxy` 本身仍持有宿主高权限，因此属于可信计算基。它不能与观察客户端混为“无写权限”；安全收益来自进程隔离和极窄的代理接口。

## 接口约束

代理只暴露：

```text
GET /v1/runtime-snapshot/{派生项目名}/probe-agent
```

客户端不能传入 socket、Docker URL、容器 ID、命令路径或任意 API 路径。代理拒绝请求体、查询参数、非 GET 方法、任意项目名及所有通用 Docker API。代理后端只执行以下固定读操作：

- 带六项固定标签过滤器的容器列表；
- 完整 64 位容器 ID inspect；
- `sha256:` 完整镜像 ID inspect；
- 完整 64 位网络 ID inspect。

明确禁止 logs、archive、exec、stats、events、image export 和全部写方法。

## 去敏与稳定性

原始 Docker JSON 不离开代理进程。传输投影不含：

- 环境变量及其值；
- health log；
- 原始标签集合；
- 宿主挂载源路径；
- network namespace 路径；
- Docker 错误正文。

代理对容器执行两次 inspect，并在中间绑定镜像、网络以及 `/proc/{pid}/stat` 的启动 ticks 和 network namespace inode。观察客户端又读取两次去敏快照，并在每次读取前后复验同一个 `OpenReleaseBound` handle。容器、镜像、PID、启动时间、重启次数、网络、socket identity 或 Release 文件任一漂移都会失败关闭，不返回部分结果。

## 运行态精确比对

观察客户端要求 Docker 声明与已审查 Compose 语义一致，包括：

- 唯一 project/service/component 标签组合；
- 完整 container/image/network ID；
- `running + healthy`，无 paused/restarting/OOM/dead，重启次数为 0；
- 非 root 用户、只读根文件系统、非特权、init、无 TTY/stdin；
- `cap_drop=ALL`、`no-new-privileges`；
- CPU、内存、PID 限额；
- 五个固定挂载目标及读写方向；
- 两个固定 tmpfs；
- 唯一 internal、非 attachable bridge 网络。

这些字段只能证明“本机 Docker daemon 当时这样声明”，不能证明 daemon 本身可信，也不能证明实际流量、镜像来源、宿主挂载 inode、state writer、quiesce 或外部时间。

## CI 验收设计

GitHub Actions 在仓库代码执行前已拉取固定摘要的 Python 测试镜像。P0-c 的 daemon 兼容门由工作流创建一个短生命周期 fixture：

- 独立 internal bridge 网络；
- 无端口、无生产挂载、只读根文件系统；
- 非 root、drop all capabilities、no-new-privileges；
- 受限 CPU、内存和 PID；
- 仅测试标签，完成后按完整 ID 删除并确认无残留。

普通与 race 两份 transcript 必须精确只运行一个 tagged 真实-daemon 用例、零 skip，并验证采集前后 container ID、image ID、StartedAt、RestartCount、PID 完全不变。fixture 只签署：

```text
LOCAL_DAEMON_FIXTURE_COMPATIBILITY
```

它不签署产品镜像或生产容器。

## 仓库候选验收证据

GitHub Actions run `39206352055` / job `117909922290` / commit `c9b466481614afe5deff1032b8b2bd1d31e59b29` 已通过：

- `DOCKER_RUNTIME_FIXTURE=PASS transcripts=2 exact=1 skips=0 race=pass boundary=LOCAL_DAEMON_FIXTURE_COMPATIBILITY`；
- `DOCKER_RUNTIME_OBSERVER_BOUNDARY=ADVISORY_LOCAL_DOCKER_RUNTIME_BOUND authorization=BLOCKED blockers=9 production=false`；
- 真实 fixture 采集前后 container/image/start/restart/PID 身份不变，并确认容器与网络清理无残留；
- `STATIC_GATE=PASS platform=linux tests=158 skips=0 schemas=11`；
- `GO_JSON_GATE=PASS files=2 semanticRunEvents=3466 packages=35 skips=0`；
- Go ordinary、race、vet 与 Draft 2020-12 schema metaschema 同步通过。

这些证据签署的是仓库候选和本机 daemon fixture 兼容性，不是生产安装、产品镜像或生产容器读回。

## 尚未形成的能力

当前仓库实现不等于已安装服务。正式部署至少还需要独立完成：

1. 创建固定系统组 `chengwang-runtime-observer`；
2. 由 root 预建 `0750 root:chengwang-runtime-observer` 的 socket 目录；
3. 将代理作为独立受限服务运行，且不把 Docker 主 socket 暴露给观察客户端；
4. 对代理二进制、服务定义和主机身份建立独立 attestation；
5. 在生产只读灰度中证明 socket peer、容器和镜像读回；
6. 在完成这些证据前继续保持恢复授权阻断。

生产部署、路由切换、停止容器和恢复动作均不属于本阶段。
