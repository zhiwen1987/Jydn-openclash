# P0-d6 产品 API 与 RBAC 实施合同（隔离候选已验收，未上线）

本阶段代码与精确场景门 `5107ebd` 已通过隔离 CI 与独立工件复核；实际结果、证据链接和未完成项见 [P0-d6 验收记录](P0D6-PRODUCT-API-RBAC-ACCEPTANCE.md)。本合同不是生产部署批准。

仅开发分支、隔离 Linux CI，不访问或修改生产。主模块 Go 1.23 不升级；独立 image-binding 后端使用 Go 1.25.8。依赖倒置：主模块 `internal/imagetrust` 只定义安全 DTO/Backend，产品 `api.New` 依赖接口；子模块 product 实现真实 Store/ManagedBind，通过候选 composition 入口注入同一个产品 API。原主入口保持未配置/失败关闭，不暗中安装新后端。

## 权限与 HTTP

- 固定 scope：tenant/site/environment 由可信服务配置，ObjectType=image-trust、ObjectID=Anchor.StoreID。请求不得指定 scope、身份、权限、bootstrap anchor、CA/token、URL、时间或 nonce。
- action：image_trust.read 对 viewer/operator/approver/auditor/admin；image_trust.update 仅 admin；image_trust.verify 仅 operator/admin。三个 action 均不支持 BreakGlass；scope/tenant/未知角色与未知 action 默认拒绝。
- GET `/api/v1/image-trust`：受保护的当前策略/撤销/消费安全摘要；无原始签名文档、密钥、token 或 Registry 网络数据。
- PUT `/api/v1/image-trust/catalogue`：原始已签 envelope，最多256KiB；仅顺序 Update，不支持 HTTP Create/重置/换 Anchor。撤销通过根阈值签入的新 catalog 送达，API admin 不能代替签名。
- POST `/api/v1/image-trust/verifications`：仅 policyId/approval/bundle/trustedRoot，规范base64；decoded预算64KiB/1MiB/1MiB，整个JSON最多3MiB。禁止未知/重复字段、非规范base64、query、Content-Encoding与错误Content-Type。
- 全部先Bearer严格鉴权、TLS或可信回环直连、固定scope RBAC；PUT与POST再要求独立写门，之后才读取body/访问后端。无AdminToken/cookie/转发头降级。方法错误也受保护。

## 后端与审计

`product.Service` 实现 imagetrust.Backend，直接调用也执行相同RBAC/写门，构造只接受已打开的Store、固定scope、预配置Registry CA/token与真实audit。Status只读，不改变Store sequence/时钟高水位；过期可被报告但不得作为当前信任消费。

认证、RBAC、输入预算、并发/速率预算与预审计必须在 RESERVED 前完成。验证采用有界非排队并发与全局固定容量限速，不为任意请求ID创建无限map。网络期间不持全局写锁，允许同一Store更新撤销。Update与Verify均预审计后变更，并写结果审计；原始输入、凭据、bundle与私钥不进入审计或响应。

审计与bbolt不是同一事务：结果审计失败必须返回 stateMayHaveChanged，不返回成功、不回收grant、不自动重试；当前service永久失败关闭。此阶段不提供跨库 exactly-once 或重启自动reconcile。审计断裂/陈旧/失败必须拒绝新的写入；鉴权失败不触发完整证据扫描或DB变更。

## 候选入口与验收

独立候选入口只打开已存在的Store与独立Anchor/身份文件；无HTTP bootstrap/reset，默认写关闭，非回环必须TLS，固定HTTP超时与请求预算，优雅关闭。不能因把接口注入 api.New 就声称现有生产二进制已升级。

验收须保留原P0-d4 234与P0-d5 379实际场景集合；父主门新增测试以真实transcript校准。除mock权限矩阵外，必须用真实authn+RBAC+evidence+Store+Sigstore+TLS Registry完成产品HTTP成功、拒重放/重开、匿名/跨域/错角色/写关闭/坏JSON零消费、无签名/旧版本catalog拒绝、网络中撤销、审计前后故障、并发/限速与无秘密输出。真实Distribution继续不适配/不执行镜像。

全部成功仍advisory/BLOCKED，九项恢复blocker不变。未完成企业IdP/MFA、多租户Store路由、WORM/外部见证、整盘回滚防护、在线自动撤销送达、发布构建/执行器、生产灰度和长期SLA。准确结果以最终验收记录为准，不保证绝对无bug。
