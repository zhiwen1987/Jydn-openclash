# P0-d11 真实产品镜像、隔离 Registry 与受管验签验收

归档日期：2026-10-23（Asia/Shanghai）。实际验收代码 `3e766db7fd3aaa905abab0f439236a7fe91d021d`。状态仅为 **implemented+tested isolated-only / ACTUAL_PRODUCT_IMAGE_MANAGED_REGISTRY_BOUND**：同轮真实产品镜像已经完成隔离 Registry、正常 TLS、测试 authority 签名/批准与镜像内产品 API 的消费/撤销/防回放生命周期；不是正式发布、安装或生产上线。仍为 `authorization=BLOCKED`、`releaseAuthorized=false`、`deviceActionsExecuted=false`，九项恢复 blocker 不变。

## 实际执行与独立重放

| 验收项 | 本轮证据 |
| --- | --- |
| 精确任务 | [绑定39826356698/job119990563178](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39826356698/job/119990563178)、[父39826356692/job119990563070](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39826356692/job/119990563070)均head=3e766db、completed/success，不是只取某个绿色步骤 |
| 旧回归不减少 | 主代理实际重放子普通/race各700 Test pair、8包及原真实Registry各3；父原日志解析各2320，完整pair指纹不变、测试用例0 fail/skip。父37个有测试包之外另有唯一domain无测试包条目，不把它算成跳过测试用例；父Python160/0skip、shell13、schema11实际通过 |
| 新合成门 | Linux检查器33/33/0skip，Docker-save元数据17个具名正反例、OCI请求头4个具名正反例及各自唯一marker均实际通过。这些是合成数据，不能替代下列真实运行 |
| 同一真实镜像 | 复用本轮D10 scratch镜像及私有Docker save字节，不另建假镜像。实际CGO=0默认程序为PID1、Go1.25.8、linux/amd64、trimpath、sourceModified=false；8个镜像文件、原config及2层diffID与独立graph严格关联 |
| 真实 Registry | 固定Distribution摘要，原服务正常TLS运行；无host端口、network none，仅loopback，无IPv4/IPv6默认出口。准备器上传后真实回拉manifest/config/全部层，并逐字节核对；独立Python检查器在CI重哈希这些回拉字节、层内容及8文件/权限 |
| 两类密码学 | message-signature与DSSE分别使用真实测试PKI/SCT/Rekor及独立批准/目录签名；每类独立Store/Audit、4组policy/grant，不使用无效JSON代替交叉制品反证。authority仅EPHEMERAL_TEST_ONLY，未把测试密钥升级为正式批准者 |
| 产品 API | 镜像默认非测试入口实际执行，每类首次成功验证HTTP200并耐久消费；重放、批准签名篡改、同PKI交叉bundle均HTTP400。每进程每分钟4次验证启动预算不放宽，无重试/重建grant换绿 |
| 重启与撤销 | 首停后重开并核对ACK/hash，再启动同一容器/同imageID/状态；在撤销前先拒绝旧消费重放。随后有效gen2安装HTTP200，gen1回滚HTTP400，未用批准撤销、错误Registry SPKI与预留grant重放均HTTP400 |
| 精确持久状态 | 每类first：seq19/gen1/journal4/audit8/ledger2（1 CONSUMED+1 RESERVED）；final：seq44/gen2/journal10/audit20/ledger3（1 CONSUMED+2 RESERVED）。健康Store/Audit重开、前缀、scope/actor、ACK、消费证据及不可回收预留均通过 |
| 独立访问观察 | Distribution原完成请求日志形成44快照，逐案例无隐藏计数间隙。2次成功产品验证导致30个不可变HTTP请求；准备上传/回拉分别计数，不冒充产品读取。另18个拒绝/只读窗口无新增Registry HTTP；TLS握手失败无HTTP日志，不等于独立记录每次握手 |
| 真实运行隔离 | 两产品实例及各自同容器重启，4份实际PID1程序SHA与静态程序相同、8份运行/退出投影一致；UID/GID10001、只读根、cap0/NNP、精确RO配置及2个RW状态目录，1CPU/内存256MiB/总memory+swap256MiB/PID128/nofile1024、无host端口/宿主socket |
| 正常退出与清理 | D11产品4次SIGTERM退出0；Registry启用5秒drain后实际status=exited、exit_code=0、running=false、oom=false、pid_zero=true、error=false。精确3个D11容器/UUID私密材料清理PASS，保留外层镜像供原D10清理；D10的5次正常停止、4类负启动、真实浏览器与精确清理门全部保持PASS，没有global prune |
| 最终独立门 | 主代理实际下载本轮安全工件，以原检查器CLI重算49份输入摘要和跨图/API/状态/PID1/清理关系，现有outcome与重算一致；另一代理用精确3e Git原bytes内存加载检查器独立重放，同样通过 |

### 摘要角色与信任边界

- 程序28,591,834B，SHA256 `02655b80faa70d717a836cc05df8636ac314dc42d5302297102750beb81548b4`。
- 本地Docker **config imageID**：`sha256:c27efe197d34ada93662e4da1df4bc382af7781371e5965b597989e174516b84`。
- 隔离Registry **manifest digest**：`sha256:f294dccc47ee9ba9294e76b901d66c6a4bb9f3a28e1505988bfdeeecab30cb8a`。这是包裹原config/原解压层的新OCI单平台清单，不冒充daemon原始Registry清单，也不把config ID当作manifest digest。
- 原2层均为OCI未压缩tar，分别28,862,976B和1,024B；顺序、diffID、摘要、内容和D10打包清单交叉一致。准备器正常TLS真实回拉发生在CI；主代理独立下载的是安全投影，**没有下载原binary/config/layer/tar并再次重哈希**。
- D10的 `registryManifestDigestVerified=false/imagePublished=false` 保留该阶段local-only含义；D11另证隔离Registry读回与种子上传，不把旧报告字段改绿，不代表向正式或外部Registry发布。

## 浏览器与工具：保留原回归，不夸大范围

本轮无前端改动，未新增人工视觉验收或Playwright运行。原真实Chrome/CDP回归实际保持：HTTP40检查/14请求、HTTPS45/16请求、镜像HTTPS45/16请求均PASS，runtime/console错误与警告/CSP/资源/越界请求均0，12份截图保留。正常私有NSS/证书链校验、3类证书拒绝、基础产品API及RBAC原检查继续通过，无mock/injected fetch/TLS bypass。

本轮实际Chrome155.0.8059.39、Node22.23.3、Go1.25.8；`product-image-packaged-contents.json` 的 `dockerToolchain` 实际投影客户端/daemon均28.0.4（API1.48）。不能套用前几轮不同工具版本。Chrome仍CI-only no-sandbox、依赖外层隔离，未证明Chrome sandbox、企业/LAN/IPv6/跨浏览器或真实公网业务体验。

## 证据保存与复现

最终[工件12446353934](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39826356698/artifacts/12446353934)，名称 `image-binding-39826356698-1`，146文件、ZIP4,177,638B，GitHub ZIP digest `f94af2694d6b0eb2db045817292e613110c3eb6e4d94c8a3753a576ead6e75f5`。主代理下载目录 `C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d11-final-3e766-c3549f2a6a57477eb32aadf218546750`；Temp和Actions保留期不是永久备份或WORM。

- checkout559条+child78条=637条源码记录（去重559路径）前后原字节相同；主代理和独立代理逐条核对精确3e Git raw blob。2个只读harness文件也与Git相符；不能拿dirty工作树或规范化换行后的文件冒充原字节。
- 389个模块记录中386个远程依赖，在线/离线原字节相同，无新增产品依赖。原700 pair SHA256 `b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999`；父2320为 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。
- 最终 `product-registry-outcome.json` SHA256 `85637714bf85e33c9c6f24d5bfeecae172e6d7982a30f4e0ba8c9d2133e90f9b`，恰49份关联输入；其自身摘要不递归加入输入集合。
- 绑定joblog API原LF1,783,868B、SHA256 `d11c7291180ce9d9510e97533f7e30027bffa04c1bbe1179696d701bc10f064e`；父原LF5,447,509B、SHA256 `179c0e1a382fcd81d1f4ebe031a2feba3d9b85c865f075e93983b189b6c81e97`。
- 未上传原始binary/tar、配置、身份/令牌、CA私钥、签名材料、NSS/profile或私有inspect。正式密钥未创建；测试材料精确清理。

在本轮安全工件目录以精确提交的检查器重放（报告输出到工件目录之外，不能手造缺失报告）：

```text
python -B check_product_registry.py verify --evidence-dir <实际下载目录> --source-commit 3e766db7fd3aaa905abab0f439236a7fe91d021d --report <目录外的新报告路径>
python -B check-go-json.py <目录>/go-test.json <目录>/go-race.json
python -B check-go-json.py --mode registry <目录>/registry-ordinary.json <目录>/registry-race.json
```

## 五次失败保留，未删除检查换绿

详见[实施合同与逐轮诊断记录](P0D11-PRODUCT-REGISTRY-CONTRACT.md)。c6环境列表顺序断言失败；65a越过后prepare失败；1c诊断确认Docker-save外围未知字段；433精确支持官方辅助元数据后，清单回读联合断言失败；711补明确OCI Accept后业务链全过，但Registry退出门失败。最后3e只启用Registry正常drain及安全退出观察，完整重新执行后才接受。

历史私有输入/退出字段按设计未上传，不能倒推出未知字段具体名字、旧HTTP状态或旧ExitCode143。修补分别依据官方[Moby导出格式](https://github.com/moby/moby/blob/v28.0.4/image/tarexport/tarexport.go)、[Distribution内容协商](https://github.com/distribution/distribution/blob/v3.1.2/registry/handlers/manifests.go)与[正常关闭实现](https://github.com/distribution/distribution/blob/v3.1.2/registry/registry.go)，没有移除严格字段、字节/摘要、TLS、持久状态、退出0或清理断言。

## 仍未完成，不据此放行生产

1. 正式Registry发行/安装、企业批准者与密钥发放/轮换/托管、独立source/builder attestation、SBOM/漏洞/许可治理、可重复构建/多架构仍缺。测试authority不是生产来源证明或完整SLSA。
2. 本阶段证明了真实CGO=0镜像进程内的Registry验证写链，**没有**证明该镜像内自动在线撤销刷新和跨库故障矩阵。手动有效目录PUT不是自动送达；D7其他路径测试不能替代下一阶段真实镜像中的异常恢复/刷新测试。
3. 健康ext4/XFS的停止重开不等于物理掉电、坏库/坏盘自修、全盘回滚防护、WORM/外部单调见证或HTTP/部署exactly-once。长期容量、资源耗尽、soak、分布式HA仍未闭环。
4. 原cmd/server默认trust backend、旧Dockerfile/M2b基础来源门、九项恢复blocker及设备执行权限不变。此候选仅已有基础产品API+trust，不是全部主App、企业IdP/SSO/MFA、订阅、多内核、DNS、节点能力与全网络功能完成。
5. 未做生产灰度/备份恢复/流量接管/长期观察，也未合并main。本轮未SSH或修改10.88.0.240/.249/.254、爱快、DNS、OpenClash、Kuma、ERP或生产Docker；只推开发分支和运行隔离CI。不提供全项目完成率、无bug、免维护或任何高可用率承诺。

操作边界见[候选操作说明](PRODUCT-CANDIDATE-OPERATOR-NOTES.md)，历史基线见[D10](P0D10-IMAGE-RUNTIME-ACCEPTANCE.md)。
