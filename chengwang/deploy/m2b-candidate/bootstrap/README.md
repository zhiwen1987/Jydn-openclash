# M2B 可路由出口 bootstrap（离线、默认阻断）

本目录只把“专用可路由 Docker bridge + 默认拒绝 nftables 出口”编译成确定性结构计划，并验证该计划与输入一一对应。它不会执行 `docker`、`nft`、DNS、DoT 或 HTTPS，不会创建网络、容器和规则，也不会生成启动门可接受的证据。

有效输入的结果仍然固定为：

```text
schema=chengwang.m2b-egress-bootstrap-report/v1
status=BLOCKED
exit=78
executionPermitted=false
acceptedEvidenceProduced=false
```

这不是失败伪装成成功，而是把首次启动前真正能证明的内容，与只能在 Linux 候选机运行时证明的内容分开。

## 离线计划闭合的内容

- 网络必须是 `driver=bridge`、`internal=false`、`attachable=false`、ICC 关闭，并固定网络名、Linux bridge 名、IPv4 私网 `/24` 至 `/29`、IPv6 ULA `/64`、网关与容器静态地址。
- 当前生产 Compose 的 `internal:true` 与真实出口互斥；本输入若仍为 `internal:true` 会直接拒绝，而不是静默生成不可用计划。
- 首次启动合同固定为 `pending-runtime`，PID、PID starttime、network namespace inode、cgroup ID、宿主 veth ifindex 全部必须为 `null`。离线阶段不得捏造这些身份。
- nft 计划使用独立 `inet` 表，并明确声明 `forward`、`input` 两个 base chain 及各自的策略 chain。base chain 的 policy 保持 `accept`，只按固定 bridge 跳转；每条规则都携带不可省略的 `chain`，归属、顺序和摘要不能依靠数组位置猜测。
- 返回方向按固定 bridge 严格排序：先接受 `established,related`，再丢弃 `invalid`，随后对该 bridge 的其他入站（包括 NEW）兜底丢弃；其他接口仍走 base policy，不受该候选影响。IPv4、IPv6 各自带明确 `nfproto`，避免跨族规则遮蔽。
- 仅允许静态 DoT 地址的 `TCP/853` 与自有 canary 静态地址的 `TCP/443`；明文 `UDP/53`、`TCP/53` 明确丢弃，其余受管 bridge 出口默认丢弃。
- bridge 到宿主的 `INPUT` 路径独立默认拒绝：DoT/HTTPS 只允许经过 `FORWARD` 到批准公网地址，不能借宿主 bridge gateway 或本地监听绕过。容器使用静态双栈地址，因此 DHCP 明确禁止；仅保留 IPv6 ND 的 RS/NS/NA（类型 133/135/136、hop-limit 255），其他宿主控制面端口全部丢弃。
- 规则顺序和每条规则的唯一计数器标签由输入确定；重复地址先合并，再记录所有 owner。不同 canary 共享 CDN IP 时会增加明确阻断项，因为一个共享计数器不能证明逐业务归因。
- 输出包含完整 nft 对象的 `nftObjectSha256`；回滚计划绑定该摘要、四条受管 chain 和精确表名。执行前仍要求相同 boot ID、相同 nft 对象/表摘要、相同运行时身份以及没有外来对象。
- 输出声明宿主全局影响边界：其他 base chain 的 hook/priority、Docker 自有规则、路由与 rp_filter 都必须在目标 Linux 主机读回，离线计划不能批准它们。

## 为什么不能从这里直接启动

容器尚未创建时，没有可验证的容器 ID、PID/starttime、network namespace、cgroup、veth、network ID 或 bridge ifindex。这是首次启动的鸡蛋问题。安全顺序必须是：

1. 先创建专用网络；普通停止态容器没有可证明的 PID/starttime/netns，不能从它直接完成身份绑定；
2. 使用独立测试 network namespace，或经过单独审计的“无网络动作 shim 启动后立即暂停”流程，才可读回并绑定 Docker network ID、bridge ifindex、veth、cgroup、容器 ID、PID/starttime、netns 与宿主 boot ID；在该机制交付前继续 `BLOCKED`；
3. 检查所有宿主 base chain hook/priority、路由、IPv4/IPv6 转发、NAT、rp_filter 和既有 Docker 规则；
4. 将结构计划编译成候选机 nft batch，在独立 network namespace 中做语法、顺序、反向流量和回滚故障注入；
5. 原子安装后再次完整读回，再用唯一测试向量触发 DoT、HTTPS 和拒绝计数器；
6. 读回容器 `/etc/resolv.conf` 并证明没有通过 Docker `127.0.0.11` embedded DNS 绕过固定 DoT；验证 TLS SNI、证书、HTTP 状态与 canary marker；
7. 只有上述运行时证据全部闭合，才可能由另一个受审计组件生成启动证据。

本工具不会跳过第 1 至 7 步，也不会把源 IP 匹配冒充进程身份。结构计划内虽然包含源地址约束，但报告始终保留 `SOURCE_ADDRESS_MATCH_IS_NOT_RUNTIME_PROCESS_IDENTITY_PROOF`。

## 输入与确定性输出

输入遵循 [`schemas/input.schema.json`](schemas/input.schema.json)，输出遵循 [`schemas/report.schema.json`](schemas/report.schema.json)，内嵌计划遵循 [`schemas/plan.schema.json`](schemas/plan.schema.json)。`validationUnix` 是审批快照时间，不读取本机时钟，因此相同字节输入会产生相同字节计划与 `planSha256`。它不能替代运行时的新鲜度复验。

关键输入包括：

- 固定项目、服务、镜像 ID、Compose SHA-256，并声明 `DIRECT_DOT_ONLY_NO_SYSTEM_RESOLVER`；该声明仍须由运行时 `/etc/resolv.conf` 与真实调用路径读回证明；
- 可路由 bridge、双栈 CIDR/网关/静态容器地址；
- nft family/table、明确区分的 forward/input base 与 policy chain、各 hook/priority；
- 固定 DoT TLS 服务器名、端口、按字节排序后的公网 IPv4/IPv6 和 TTL 窗口；
- 自有 canary 合同 SHA-256、主机名、`TCP/443`、按字节排序后的静态公网地址和 TTL 窗口；
- 全局影响审批必须是 `unproven`，因为离线输入不能批准宿主现状。

地址列表按 IP family 与 packed bytes 排序，不能重复；主机名必须为小写规范 DNS 名。私网、保留、环回、链路本地、多播、IPv4-mapped IPv6 均拒绝用作出口目的地址。

## 命令

输入、报告必须用绝对路径。输入在两次有界读取之间必须保持 inode、大小、mtime、ctime 和内容一致；JSON 禁止重复 key 与非标准数字。POSIX 下输入及祖先必须 root 所有且不可由组/其他用户写，输入权限不宽于 `0600`；输出父目录必须 root:root `0700`，输出以 no-clobber 方式发布为 `0600`。

```sh
python3 -B compile_egress_bootstrap.py compile \
  --input /root/private-evidence/bootstrap-input.json \
  --output /root/private-evidence/bootstrap-report.json
# 预期退出码：78

python3 -B compile_egress_bootstrap.py validate \
  --input /root/private-evidence/bootstrap-input.json \
  --report /root/private-evidence/bootstrap-report.json
# 预期退出码：78
```

`validate` 会重新编译并要求报告逐字段完全相等，同时重算内嵌计划摘要。报告被篡改、输入改变、路径替换、JSON 重复 key 或 schema 字段偏移都会返回退出码 `2`。

## 平台与验收边界

Windows 单元测试验证纯编译、规则顺序、双栈、TTL、共享 IP、摘要、no-clobber 和失败路径；Windows 无法证明 Linux UID/GID、目录 fd、Docker bridge、cgroup/veth 或 nftables 语义，因此报告会额外携带 Windows blocker。Linux 候选机仍必须运行独立的真实网络与 nft 故障注入验收。

运行测试时禁止生成仓库内 pycache：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

测试通过只表示离线编译器合同正确，不表示候选出口已部署、已生效或可启动。
