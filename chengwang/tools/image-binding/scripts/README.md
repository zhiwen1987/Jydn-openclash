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

固定 Go 1.25.8 的 [`go mod verify` 实现](https://github.com/golang/go/blob/go1.25.8/src/cmd/go/internal/modcmd/verify.go)会对 build list 中的本地替换模块尝试 archive 校验。这些模块没有远端 zip，因此不能直接把其报错当作远端依赖验收通过。

workflow 先 `go mod download all`，保存原始 `go list -m -json all`，严格检查仅有两个指定本地 replace。`module-verification.py prepare` 在外部临时目录生成辅助 module，保留所有远端精确 MVS 版本并复制原始 `go.sum`。任何远端缺少原始 archive 或 go.mod pin 都拒绝继续；三个本地 module 的 `go.mod/go.sum` 原始摘要单独绑定。

辅助 module 的远端 MVS 集合必须与原图完全相同，不能存在 replace。所有远端 zip、解压目录、module metadata 都必须存在，download 结果及 cache ziphash 必须与原始 `go.sum` 一致，再运行官方 `go mod verify`。在线准备和真实断外网后的检查都执行，任何远端校验错误都会使门禁失败；不会忽略错误、禁用内容校验或升级主 module。

在线下载后立即保存 `evidence/go.sum.candidate` 和下载退出状态。候选锁文件只供审查；下载失败仍使步骤失败，下载造成的源码锁文件变化仍由 `git diff --exit-code` 拒绝，不会自动批准或提交。断外网阶段另存 `parent-restoreimage.json`，记录主 module OCI 校验器的实际 Linux 测试事件；它不混入子 module 的三 package 门禁，也不自动更新主门禁的测试指纹。

脚本中的 `GOMEMLIMIT` 是软目标。Registry 容器另有硬 memory/CPU/pids 上限，Go 测试进程另有超时与有限 ulimit；这些条件不代表产品部署的完整资源隔离。所有成功报告仍为 advisory，固定 `authorization=BLOCKED`、`production=false`。
