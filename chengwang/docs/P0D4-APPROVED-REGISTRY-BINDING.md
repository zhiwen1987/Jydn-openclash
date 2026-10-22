# P0-d4 独立批准与真实 Registry 读回绑定

日期：2026-10-22（Asia/Shanghai）。范围限开发分支与隔离 CI，禁止改生产。

## 本次候选实现

新增独立 `tools/image-binding` 模块，使用标准 Ed25519 验证独立批准文档，再以 P0-d3 标准 Sigstore 验签关联主项目的 OCI 内容图；Registry 身份同时绑定主机、仓库、批准 IP、正常 TLS 和叶公钥 SPKI。具体接口、输入预算与兼容范围见 [模块说明](../tools/image-binding/README.md)。

发现并补充两项跨模块合同：checkpoint 的签名树大小必须等于包含证明的树大小；批准与主 OCI 图共享规范引用/平台校验，避免接受后无法读回的 IPv6/仓库名称。普通负例同时覆盖不同签名根，以及同一 CA、叶证书和日志根下不同真实 manifest，不能只靠更换根触发拒绝。

## 已完成的隔离验收

验收代码提交为 `90299930429c147ebde14c71739159ea20c5e6d7`，分支 `codex/chengwang-security-hardening`。以下结果均已实际读回，不是根据计划或文件存在推断：

| 范围 | 实际证据 | 已确认结果 |
| --- | --- | --- |
| 新绑定库 | [run 39749344500 / job 119725676913](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39749344500/job/119725676913) | Go 1.25.8 Linux；普通/race 各 234 个 Test 场景、3 包、0 skip，vet 通过，两个集合相同 |
| 真实 Distribution | 同一任务，`registry-ordinary.json` / `registry-race.json` | 固定摘要的官方 Registry 3、独立 TLS CA/叶公钥批准、合法惰性 OCI 镜像实际上传后读回；普通与 DSSE 各通过，普通/race 各 3 个 Test 事件、0 skip；不运行产品镜像 |
| 原主项目 | [run 39749344508 / job 119725677234](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39749344508/job/119725677234) | Go 1.23.12 基线；普通/race 合计 4134 个语义 run 事件、36 包、0 skip；158 个 Python 测试、11 份 schema metaschema 与既有真实 Docker/恢复门通过 |
| 标准验签回归 | [run 39746175662 / job 119715058390](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39746175662/job/119715058390) | 普通/race 各 328 场景、2 包、0 skip；checkpoint 树大小新回归通过。该 run 的 `86ed46c` 到上述验收提交之间，整个 `tools/image-verifier` 无差异 |

最终集成者下载了 artifact `image-binding-39749344500-1`，重新执行严格 JSON 门；逐份将 26 个模块文件的 CI SHA256 与验收提交的 Git 原始 blob 比对，全部一致，before/after manifest 一致。并独立读回主项目与标准验签任务结果。

依赖证据保持原始 386 项远端 MVS 集合及版本；全部 archive/go.mod pin 来自原始锁，官方 `go mod verify` 在线及真实断外网后均通过。两个无远端归档的本地模块只在验证专用临时投影中使用合法 dotted alias，严格绑定到原目录；没有提升依赖、替换远端模块或用该投影编译产品。三个原模块及临时锁不可变；真实编译始终 `GOWORK=off`。实现与审计约束见 [运行器说明](../tools/image-binding/scripts/README.md)。

单位测试的外网接口及 IPv4/IPv6 外部连接均被禁止，只有 loopback TLS。真实 Registry 另用唯一 internal bridge，无宿主端口和持久卷、非 root、只读根文件系统、无 capabilities、NoNewPrivs 及资源上限；普通/race 均验证无默认路由及外部连接。最终 job 日志实际出现 `REGISTRY_FIXTURE_CLEANUP=PASS only_owned_objects=true ephemeral_private_keys_removed=true`。这是临时测试资源清理证据，不是生产回滚演练。

独立复核另确认 Distribution 服务日志版本为 3.1.2，48 次不可变 GET/HEAD 全部成功。附件共 29 文件，没有 PEM 文件或私钥 PEM 块。附件包含网络原始 inspect 及校验后的容器安全投影，但不含完整容器 inspect 或独立清理文件；清理采用官方 job 日志交叉佐证。模块缓存没有整体上传，下载后不能离线重算其所有原始字节，只能核对原始图/pin、已绑定脚本及 CI 中实际执行的官方校验结果。这些是证据可重放性的已知限制。

以上完成的是候选库及测试镜像链路的隔离验收，不是澄网真实发布镜像准入、产品控制面集成或正式上线。结果始终 `ADVISORY_APPROVED_REGISTRY_SIGNATURE_BOUND / authorization=BLOCKED`，九项恢复 blocker 不变。

## 验收中发现的问题与处理

本机 Go 工具链/依赖缓存多次出现字节损坏、NUL 和 checksum mismatch，编译未能稳定完成。失败不计作通过；没有关闭 checksum、替换预期摘要或将损坏缓存当成验证依据。阶段验收转用独立 Linux CI。CI 对首次补全 archive pins 导致 go.sum 变化仍必须失败；仅导出候选锁文件用于审查，不能自动批准。

- 首轮新增测试后，主项目旧指纹正确失败。独立复核普通/race：原 276 场景全部保留，新增 57 项，共 333；按实际事件更新计数及大小写敏感摘要。另纠正标准验签门一个子测试名称。
- `require-all` 辅助模块与三 Main 工作区分别改变了依赖图，均被精确门拒绝。没有合入这两份候选依赖锁；最终仅两本地名称投影保持原远端图不变。
- Go 精简 SDK 的 blob 响应缺少 Content-Type，严格读取器正确拒绝。普通测试显式适配该夹具，并新增原 SDK 的实际拒绝回归；没有放宽生产读取器。真实 Distribution 测试不使用任何补头适配。篡改负例另要求合法成功基线与实际命中计数，避免提前失败造成假通过。
- GitHub 对固定版本 Actions 的 Node 20 退役给出警告，runner 实际强制使用 Node 24；任务成功不等于不存在警告。后续 Actions 升级须另行审查，不能静默更换固定 SHA。

## 未完成与不承诺项

- 独立批准公钥/文档摘要/revision 的产品可信存储、发放、轮换、吊销与持久化防回放尚未实现；目前是明确调用参数与测试密钥。
- 没有审批源码提交、builder 工作流或构建 provenance 内容语义；DSSE predicate type 匹配不代表这些字段已经批准。实际密码学身份和精确镜像摘要绑定不能替代完整构建供应链准入。
- 没有签发澄网真实发布镜像，没有接入部署执行器、运行容器身份或恢复操作；结果始终 advisory/BLOCKED，九项 blocker 未解除。
- Registry 认证 challenge、跨主机重定向、index/多平台自动选择及完整生态兼容性未实现；不支持就拒绝，不静默降级。
- 测试只证明对应提交和列明场景。没有生产灰度、故障演练、长期观察、全项目完整安全审计或生产 SLA 证据。
- CI artifact 保留 14 天，不是长期不可变审计库。真实生产接入仍需进程级硬限额，SDK 密码学调用不保证可在 context 截止时间中途打断。
- M2b 主动探测、M3 受控发布、M4 DNS/自治闭环仍不能因本阶段测试而认定完成。

本阶段没有访问、重启或修改 .240/.249/.254，没有修改爱快或现网 OpenClash。后续真实部署必须另行取得授权、备份并独立验收。
