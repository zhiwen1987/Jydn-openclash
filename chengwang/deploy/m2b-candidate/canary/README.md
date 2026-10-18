# 静态自有 Canary / IP 合同（只读、默认阻断）

本目录定义主动探针第一跳使用的、可审核的静态 `域名 -> CNAME 链 -> IPv4/IPv6 -> TLS -> HTTP` 预期合同。它把目录原始字节摘要、有效期、所有权证据摘要和每个探针的严格预期绑定在一起，避免把实时公网 DNS 的偶发漂移直接当作允许出口。

校验器只读合同和 catalog，不访问 DNS、TLS、HTTP 或 Docker，也不修改输入。安全读取会拒绝相对路径、任一路径组件中的符号链接、非普通文件、硬链接、不可信 owner、组/其他用户可写路径、超限文件、重复 JSON key、`NaN/Infinity`、过深 JSON 和读取过程中发生的变化。输入会独立读取两次，并比较 inode、mode、nlink、size、mtime、POSIX ctime、内容和 SHA-256。

POSIX 上输入和输出最终分量通过已校验的父目录 `dirfd` 打开；合同与 catalog 应以 `0600`（或受控同组只读 `0640`）安装，不能直接依赖常见 umask 产生的 `0644`。报告以 `0600` 临时文件、文件与目录 `fsync`、硬链接 no-clobber 原子发布。链接后的校验或 `fsync` 失败会尽力删除输出；若底层文件系统同时拒绝删除，残留文件仍只有 `BLOCKED` 语义，必须由独立恢复流程清理，不能当作完成证据。

## 严格合同

- schema：`chengwang.static-canary-contract/v1`
- 报告 schema：`chengwang.static-canary-validation/v1`
- 合同最长 24 小时；签发、审批、解析时间不得来自未来，合同和解析记录不得过期。
- 每个 catalog 探针必须恰好出现一次；重复、遗漏、未知 `probeId` 均拒绝。
- CNAME 链必须从 catalog 主机名开始，只能经过 catalog 明确允许的名称，重复名称视为循环并拒绝。
- 地址必须为规范形式的公网全局单播 IPv4/IPv6；私网、回环、链路本地、组播、文档网段、CGNAT、NAT64、6to4、Teredo、元数据地址和 IPv4-mapped IPv6 均拒绝。
- 同一探针内重复 IP 拒绝；不同探针共享 CDN IP 合法，但会显式列入 `sharedAddresses`，不得据此声称逐业务独立归因。
- TLS 的 SNI 与校验主机名必须等于 catalog 主机名；证书 DNS 名期望集合必须精确覆盖该主机名，只允许完整主机名或最左侧单标签通配符；最低版本固定 TLS 1.2。
- 自有 canary 的 HTTP 语义固定为 `GET + HTTPS/443 + 精确 200 + 非空 marker`，并与 catalog 的路径、marker、body 上限完全一致。403/429/重定向不能冒充成功。
- 所有权和审批只保存证据的 SHA-256，不保存凭据、token 或证书私钥。
- 所有端口、状态码、时间、周期、超时、TTL 和 body 上限必须是真正的 JSON integer，布尔值和浮点值即使数值相等也拒绝；并校验 OpenClash 探针现有的范围及 TTL/周期关系。

## 为什么验证成功仍为 BLOCKED

静态合同只能证明“预期是自洽并绑定的”，不能证明运行时确实观察到了指定 DNS 答案、证书、HTTP 状态和 marker，也不会替审批或所有权证据摘要做密码学验签。因此成功报告仍固定为：

```text
schema=chengwang.static-canary-validation/v1
status=BLOCKED
reason=VALID_CONTRACT_IS_NOT_START_EVIDENCE
acceptedStartEvidenceEmitted=false
exit=78
```

该报告绝不能直接提供给 `start-verify-probe-agent.sh`，也不会生成它接受的 schema。后续仍需独立的运行时 DNS/TLS/HTTP 观测、出口隔离和唯一测试流量归因。

Windows 分支只能提供路径逐组件、文件身份、二次内容摘要和 no-clobber 发布等尽力校验。Windows `chmod` 不等于 NTFS ACL 隔离，并且本工具无法在那里提供 POSIX uid/gid、ctime 与 `dirfd + directory fsync` 等价证明；报告会写入 `filesystemAssurance=non-posix-best-effort-blocked` 及对应 blocker。只有 Linux/POSIX 候选机回归通过后，文件系统证据门才可能继续推进。

## 使用

```sh
python3 static_canary_contract.py validate \
  --contract /root/private-evidence/static-canary-contract.json \
  --catalog /root/private-evidence/catalog.json \
  --output /root/private-evidence/static-canary-validation.json
```

在 POSIX 候选机执行前先显式安装权限：

```sh
chmod 0600 /root/private-evidence/static-canary-contract.json \
  /root/private-evidence/catalog.json
```

输出文件必须尚不存在。退出码 `78` 表示“合同有效，但仍禁止作为启动证据”；退出码 `2` 表示合同或文件安全校验失败。

测试只使用合成域名、公开递归服务地址作为格式样本和不可逆假哈希，不包含任何真实节点、凭据或批准。
