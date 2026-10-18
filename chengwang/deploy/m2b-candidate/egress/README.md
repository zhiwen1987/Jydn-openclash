# 宿主出口证据候选（只读、默认阻断）

这里的工具只负责采集与验证，不安装 nftables 规则、不启动/停止容器、不执行网络请求，也不接触生产环境。

## 已实现的闭环边界

- `capture` 只执行固定的 `docker inspect`、`docker network inspect`、`nft --json list ruleset`，并读取当前 boot ID、容器 PID/starttime 与 network namespace inode。
- 命令原始输出只在内存中限长处理。落盘的是严格最小投影，不包含 Docker `Env`、标签原文、挂载、宿主完整网络或非管理 nft 表。
- `verify` 对两个独立时间点的最小快照做严格验证：容器、Compose 项目、镜像、Docker 网络、PID/starttime、network namespace、宿主 boot ID、nft 结构摘要必须保持一致。
- nft 管理表中只允许一个入口链和一个策略链；入口必须按准确 bridge 名称跳转。
- IPv4 与 IPv6 都必须有末尾默认丢弃规则。
- 固定 DoT 只允许计划中的公共 IP `TCP/853`；探针只允许新鲜解析计划中的公共 IP `TCP/443`。
- 每条已声明 DoT、探针、IPv4 拒绝、IPv6 拒绝规则的计数器都必须在前后快照间增长。
- 解析计划原始字节的 SHA-256 被编码为 `evidence:<sha256>`，并要求 OpenClash 探针策略的 `runtimeEvidence` 精确引用该值，从而把审批策略绑定到完整 IP/CNAME/TTL 快照。

## 为什么当前仍为 BLOCKED

现有 `start-verify-probe-agent.sh` 明确要求 Docker 网络 `Internal=true`；真实 TCP/853 与 TCP/443 出口证据又要求网络可路由，即 `Internal=false`。两者不能同时成立。

因此，即使 Docker/nft/计数器验证全部通过，本工具也只生成：

```text
schema=chengwang.host-egress-verification/v1
status=BLOCKED
reason=INTEGRATION_CONTRACTS_INCOMPLETE
exit=78
```

此外，普通计数器增量还不能证明流量来自唯一的验收测试向量，同一个目标集合的共享计数器也不能逐 IP 归因；解析计划的 TTL/CNAME/IP 虽会被严格校验，但不能离线证明它确实来自指定 DoT 会话；首次启动也存在“容器未启动就无法产生计数器”的先后矛盾。需要引入受控测试 network namespace 或独立签名验证器后才能闭合。

Python 端镜像了当前 Go `ValidatePublicIP` 的显式禁止网段，并在测试中覆盖关键边界；两个实现以后仍可能发生语义漂移。因此正式解锁前还必须增加由同一 Go 校验器消费解析计划的跨语言一致性门。

它不会生成启动门接受的 `chengwang.m2b-probe-egress-evidence/v1` 成功文件，避免把互相矛盾或不可归因的证据伪装成已验收。

## 使用方式（候选机，非生产）

```sh
python3 host_egress_evidence.py capture \
  --container-id FULL_64_HEX_CONTAINER_ID \
  --docker-bin /usr/bin/docker \
  --nft-bin /usr/sbin/nft \
  --nft-family inet \
  --nft-table APPROVED_MANAGED_TABLE \
  --output /root/private-evidence/before.json

# 由独立验收流程产生允许与拒绝流量；本工具不会代发流量。

python3 host_egress_evidence.py capture \
  --container-id FULL_64_HEX_CONTAINER_ID \
  --docker-bin /usr/bin/docker \
  --nft-bin /usr/sbin/nft \
  --nft-family inet \
  --nft-table APPROVED_MANAGED_TABLE \
  --output /root/private-evidence/after.json

python3 host_egress_evidence.py verify \
  --before /root/private-evidence/before.json \
  --after /root/private-evidence/after.json \
  --plan /root/private-evidence/approved-plan.json \
  --catalog /root/private-evidence/catalog.json \
  --policy /root/private-evidence/egress-policy.json \
  --compose /root/private-evidence/compose.probe-agent.yaml \
  --candidate-root /var/lib/chengwang-m2b-candidate/INSTANCE \
  --project PROJECT_NAME \
  --image-id sha256:FULL_64_HEX_IMAGE_ID \
  --container-id FULL_64_HEX_CONTAINER_ID \
  --output /root/private-evidence/blocked-report.json
```

所有输入必须是绝对路径、无符号链接路径组件、root 所有、单硬链接且权限不宽于 `0600`；其全部祖先目录也必须 root 所有且不可被组/其他用户写入。输出父目录必须是 root:root `0700`，输出文件必须尚不存在，并以 `0600` 和 no-clobber 方式创建。测试夹具不包含真实节点、凭据或真实批准。

`docker` 与 `nft` 不接受任意 CLI 路径：真实路径只能是代码内固定白名单中的 `/usr/bin/docker` 以及 `/usr/bin/nft` 或 `/usr/sbin/nft`，路径本身不得为符号链接，全部祖先必须可信。工具先打开并校验二进制，再通过继承的 `/proc/self/fd/<fd>` 执行同一 inode，降低 check-to-exec 替换风险。子进程使用清理后的固定环境，并显式连接本机 `/var/run/docker.sock`，不会继承 `DOCKER_HOST`、`DOCKER_CONTEXT` 或代理变量。

每个只读命令都运行在独立进程会话中。超时、输出超限、解析异常或“stdout/stderr 已关闭但进程仍挂起”时，工具都会无条件尝试终止整个进程组，再 `wait` 回收直接子进程并关闭管道；即使直接子进程已快速退出，继承管道的挂起孙进程也不能逃逸。

当前文件路径约束使用逐组件 `lstat`、`O_NOFOLLOW` 与 fd 后验校验；它还不是 Linux `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` 的单次内核路径解析，因此 accepted 阶段仍需迁移到 `openat2` 或等价的预打开目录 fd 工作流。此残余不影响当前始终 `BLOCKED` 的状态。

当前 BLOCKED 报告还明确记录三项未闭合内容：Compose 目前只绑定字节摘要、尚未由本工具独立解析语义；Python 对目录/策略的复刻必须改为调用共享 Go 校验器；宿主其他 nft base chain 的整体效果尚未形成独立证明。

多个业务探针解析到同一个 CDN IP 是合法情况：单条解析记录内重复 IP 会拒绝，不同探针之间则合并去重生成 nft set；这仍不等于逐业务、逐 IP 的独立计数证明。
