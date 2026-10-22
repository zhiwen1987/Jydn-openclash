# 镜像批准与 Registry 绑定的 CI 运行器

这些脚本只验证候选库的兼容性，不部署产品或批准镜像。真实结果取决于对应提交的 CI transcript，脚本存在不表示验收已通过。

`run-linux-ci.sh RUN_ROOT GO_BINARY GOMODCACHE` 在新的 network/mount namespace 中启用 loopback，禁止外部接口和默认路由，将整个 checkout 与模块缓存绑定为只读，清空 capabilities 并启用 no-new-privileges。编译缓存、临时目录与测试二进制仅写入 `RUN_ROOT`。随后运行普通/race/vet、严格 JSON 门，并在同一个隔离环境编译带 `registrycli` tag 的普通/race 测试二进制。

`run-registry-fixture.sh` 使用这些二进制，在唯一、带 ownership label 的 Docker `--internal` bridge 上运行真实 CNCF Distribution Registry。容器为非 root、只读根目录、无 capabilities、无宿主端口；仅挂载测试 TLS 配置及服务器证书/私钥，存储在有上限的 tmpfs。客户端进入 Registry 的 network namespace，以固定 `127.0.0.1` 与固定证书域名访问 TLS，不需要发布宿主端口。批准签署使用独立离线读取的服务器公钥证书，CA 私钥不挂进容器。

测试 Registry 使用官方 `library/registry` 镜像，固定 Linux/amd64 manifest：

```text
registry:3@sha256:1290056e2357eceb0c047cb60ae9abb370305a218e2df650eb8d3ea021b1c151
```

该 digest 从 Docker Hub `library/registry:3` 索引 `sha256:be9a7062dd7e3316e5c0368e42740dc991a9ceb5d382317675a8738db0112af0` 中解析获得。它属于测试服务器，不是已批准的澄网产品镜像。官方部署及 API 合同见 [Distribution 部署](https://distribution.github.io/distribution/about/deploying/) 与 [Registry HTTP API V2](https://distribution.github.io/distribution/spec/api/)。

退出 trap 只删除本次唯一名称且 ownership label 精确匹配的容器、网络，以及两个明确的临时私钥路径。测试日志和 JSON transcript 放在 `RUN_ROOT/evidence`；私钥留在它之外并在 trap 中移除，不上传或提交。Registry 测试生成合法 tar/OCI 材料并上传，但不会执行产品镜像。

## 本地 replace 的校验

固定 Go 1.25.8 的 [`go mod verify` 实现](https://github.com/golang/go/blob/go1.25.8/src/cmd/go/internal/modcmd/verify.go)会跳过主 module；本项目两个无域名 module 名称则使缓存路径校验报错。合法的 dotted 路径在没有任何缓存 archive/解压目录时，官方实现正常跳过。把所有 selected module 提升为直接 require，或者把三个本地 module 提升为 workspace Main，都会改变原始 lazy pruning；本运行器不使用这些方案。

workflow 始终在 `GOWORK=off` 下下载并记录原始 MVS 图，严格检查两个指定本地 replace 和固定 SDK。`module-verification.py prepare` 在外部临时目录复制原始子 module 的 `go.mod/go.sum`，仅将两个本地 require/replace 的名称改为固定 `chengwang-ci.invalid/local-main`、`chengwang-ci.invalid/local-verifier`，并将 replace 目标设为原始源码绝对目录。其他原始声明字节保持不变，不运行 tidy，不提升远端依赖。Go 1.25.8 [官方本地 replace 加载实现](https://github.com/golang/go/blob/go1.25.8/src/cmd/go/internal/modload/modfile.go)允许这种本地 module 声明路径差异。三个源 module 的 `go.mod/go.sum` 原始字节摘要单独绑定，同一 module/version 的跨文件 checksum 冲突会拒绝。

验证图必须恰好包含一个临时 Main、两个固定版本 `v0.0.0` 的本地 alias；alias 的目标、Dir、GoMod 必须匹配原始源码，禁止 alias 缓存归档、解压目录或下载元数据。其余远端 module 的集合、版本必须与原图完全一致，禁止任何远端 replace。所有远端 archive/go.mod pin 仍必须存在于原始子 module 的 `go.sum`，实际归档、解压目录和 go.mod 必须存在，下载结果和缓存 ziphash 必须匹配，再执行官方 `go mod verify` 核对实际 zip 与解压源码。本地源码只作独立 manifest 绑定，不宣称通过远端 archive 校验；编译与测试始终使用原始 module。

临时 module 的 `go.sum` 是原始子 module 锁的逐字复制，任何新增 checksum 都使原始不可变 manifest 检查失败，不自动重设基准。每次在线命令后导出临时锁候选与退出状态，下载或校验失败仍使步骤失败；源锁变化仍由 `git diff --exit-code` 拒绝。离线阶段源码、模块缓存及整个临时验证目录都挂载为只读，重新执行精确图、缓存 pin 和官方 verify 检查。

`evidence/go.sum.candidate`、`auxiliary*.go.sum.candidate` 仅供审查，不能自动升级或污染真实依赖。断外网阶段另存 `parent-restoreimage.json`，记录主 module OCI 校验器的实际 Linux 测试事件；它不混入子 module 五 package 门禁，也不自动更新主门禁指纹。若此前步骤失败，该父测试记录可能尚未生成；artifact 只保存实际已有文件。

P0-d5 新增 `trustcatalog`、`truststate`；P0-d6 再增 `product`、候选命令，普通/race 门现精确要求七个 package，分别保留 P0-d4 的 234 与 P0-d5 的 379 场景固定 SHA256，防止新增场景掩盖旧场景缺失。状态测试临时目录必须是本次 RUN_ROOT 下的私有原生 ext4/XFS；包含真实子进程锁、`os.Exit` 后 reserved/consumed 重开，不能称为真实掉电证明。真实 Distribution 的两类签名在 ordinary/race 中分别要求 managed 成功、关闭重开和拒重放的精确输出，不能拿 SDK 测试服务替代真实 Registry。

P0-d6 在原模块 before/after 清单之外，增加全部 tracked `chengwang/**` 与本绑定 workflow 的 checkout before/after SHA256 清单，覆盖父 API/RBAC/合同和兄弟验签器等真实源码依赖，不读取无关生产 OpenClash 配置。普通门还实际构建 trimpath 候选命令，记录 binary SHA256、`go version -m` 和无副作用 `--help`；二进制不上传。候选真实 run/HTTP/TLS 测试不等于正式签发的发布镜像或真实生产进程部署。父项目新增 API/RBAC/合同完整测试指纹基于实际 Linux transcript 校准，并独立核对原 2067 个 Test 场景全部保留；不把 Fuzz seed 混入语义 Test 计数。

脚本中的 `GOMEMLIMIT` 是软目标。Registry 容器另有硬 memory/CPU/pids 上限，Go 测试进程另有超时与有限 ulimit；这些条件不代表产品部署的完整资源隔离。所有成功报告仍为 advisory，固定 `authorization=BLOCKED`、`production=false`。
