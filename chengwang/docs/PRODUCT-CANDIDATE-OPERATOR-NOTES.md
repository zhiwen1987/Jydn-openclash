# 完整产品可信候选：操作说明

适用范围：P0-d9/D10 源码候选，**不是生产部署授权**。实现合同与实际验收结果分开；只有当次验收报告才证明哪些命令/流程真实执行过。下列路径均为示例，不代表已在任何主机创建或运行。

P0-d10 已在隔离CI真实构建并运行独立scratch候选镜像，详见 [D10验收](P0D10-IMAGE-RUNTIME-ACCEPTANCE.md)。它未签名发布/安装，没有可直接用于生产的Registry地址；本地imageID不是Registry manifest。CI的 `product-image.test` 仅创建惰性签名测试数据/一次性身份与证书，**不是正式bootstrap或可信密钥发放工具**，不要复制其材料到生产。正式镜像来源、批准及生产安装仍须另行完成。

## 两个入口模式，不要混淆

| 启动方式 | 作用 | 仍未发生 |
| --- | --- | --- |
| 原 `cmd/server` | 共享 Go1.23 产品运行时，沿原环境配置 | 不因重构自动载入可信后端，不升级现网 |
| `image-trust-api -config ...` | 既有 image-trust 窄路由候选 | 不开放其他产品子系统 |
| `image-trust-api -config ... -product-config ...` | 同一完整产品 API 加真实可信后端，共享审计，Go1.25.8 候选 | 不启用发布/Shadow operation 写入、Mihomo 连接或设备执行 |

完整模式固定 `candidate` 环境和 TLS，即使只监听本机也不能降级 HTTP。此模式不读取或覆盖 `CHENGWANG_*` 环境配置；遗留的发布开关不能替它开启权限。可信 catalog 的写门仍在独立私有 trust 配置中显式控制，默认关闭，不受页面输入影响。

## 准备前置

1. 必须是隔离的候选目录和实例，不复用生产数据、端口或网络路径。正式安装/镜像发布仍未完成，本说明不提供绕过其门禁的命令。
2. 已通过受控带外流程取得 Anchor、有效阈值签名目录、实际 trust Store 和匹配的已有 Audit。两个入口均不提供 HTTP bootstrap。缺 Store 或审计 checkpoint 会拒绝启动，不能删库重建来“恢复”。
3. 使用最小权限静态身份配置；image-trust 的固定 scope 与 control-plane scope 分别授权。auditor 可看可信历史，但仅 auditor 角色不能读取通用 operations；viewer 能读已授权 control-plane，但不能看可信历史。不要为方便统一发 admin。
4. 证书链必须由访问端正常信任，SAN 必须匹配实际访问地址，时间有效；服务器拥有对应私钥。CI 的私有 NSS CA 只用于一次性测试，不是企业生产 CA 发放/轮换方案。
5. 配置、身份、Anchor、CA、TLS 文件满足既有私有读取边界：绝对规范路径，无符号链接；直属目录 0700、文件 0600、当前运行 UID/GID、单硬链接。DataDir 必须已存在且私有，AuditDir 精确为 `DataDir/evidence`。
6. `webDir` 可空；若开启，须为实际 Vite build 输出，只提供 trust entry 可达资源。不是源码路径、任意文件共享，也不开放整个主 App 的演示快照。

## 完整产品配置示例

私有 product 配置示例，所有字段使用精确大小写，禁止未知/重复字段：

```json
{
  "addr": "127.0.0.1:7812",
  "dataDir": "/srv/chengwang-candidate/data",
  "identitiesFile": "/srv/chengwang-candidate/private/identities.json",
  "tlsCertFile": "/srv/chengwang-candidate/private/server-cert.pem",
  "tlsKeyFile": "/srv/chengwang-candidate/private/server-key.pem",
  "tenantId": "candidate-tenant",
  "siteId": "candidate-site",
  "environment": "candidate",
  "managementObjectId": "candidate-control"
}
```

已有 trust 配置中的 `addr/identitiesFile/tlsCertFile/tlsKeyFile/tenantId/siteId/environment` 必须与它完全一致；`auditDir` 必须为示例的 `/srv/chengwang-candidate/data/evidence`。`storePath/anchorFile/registryCAFile` 等仍来自真实受管材料，不在此伪造签名或批准文件。完整模式无“自动采用另一份配置”或“回退到环境变量”的分支。

具备全部前置条件、隔离验收与必要授权后，候选管理员可使用：

```text
image-trust-api -config /srv/chengwang-candidate/private/trust.json -product-config /srv/chengwang-candidate/private/product.json
```

该示例不是本机或服务器已执行记录。不要同时启动两种候选去争用同一个 Store/Audit；锁冲突不是删锁或重建状态的理由。

## 查看、停止和异常处理

- 同源访问 `/trust.html`，按[只读控制台说明](TRUST-CONSOLE-OPERATOR-NOTES.md)显式连接。其他产品 API 的存在不证明对应数据面、企业模块或真实业务已接入；`snapshot` 的 demo 标记不能被忽略。
- 目录、来源新鲜度、审计健康各自判断，未知/过期不当作正常。`authorization=BLOCKED` 和 `deviceActionsExecuted=false` 必须保留。
- 使用正常进程停止信号。运行时停止 admission、取消请求及 worker，等 handler 与 worker 结束后再关库。超时会明确失败并保留资源，不报告“安全停止成功”；不能复用这个失败进程启动新服务。
- `runProduct` 配置/存储/后台异常返回通用候选错误，不打印私钥、身份或来源凭据。排查从权限、证书、固定 scope、完整性及受保护日志入手，不能关闭 TLS/RBAC/签名/时效来换绿。
- 备份/回退首先停止旧实例并确认退出，遵循受管信任的单调代次和已消费账本事实。代码回退不授权回滚 catalog、Anchor 或 grant；恢复旧磁盘快照不能当作合法回收授权。
- 自动恢复仅健康两库间的审计补投递，不修坏盘/坏 checkpoint，不重做业务，不证明客户端已经收到成功。此模式未安装 supervisor、IdP、生产证书自动轮换、分布式 HA 或完整灾备。

当前测试只允许临时受控本地 CA/loopback；没有证明真实企业证书、公共域名、全部浏览器、长期稳定性或生产部署。正式切换必须另行明确范围、先备份、验证恢复，再做灰度、读回和观察。
