# 操作、恢复与私有资料交接

此页不含秘密值。历史路径必须先只读核实存在、权限、时间和完整性，不得盲目执行旧回退。

## 主机与目录

- 249：Compose /root/dpanel/compose/lan-center/docker-compose.yml（JSON 内容）；数据根目录 /root/dpanel/compose/lan-center/data，实际绑定以 docker inspect 为准。
- 0.2 状态 /opt/clash-center-ui/state.json；历史回退 /opt/clash-center-ui/rollback.sh。
- 0.2 部署备份 /opt/clash-center-ui/backups/1793129830767687354。
- 本轮完整在线备份 /var/backups/clash-integrated-1793135667，含 control/kuma、Compose 与容器私有描述；这是密码重置前副本，不可直接用它验证新认证。
- Kuma 成功密码变更备份 /var/backups/clash-integrated-kuma-auth-1793136978，含在线数据库及受保护恢复脚本 restore-account.py。CAS 在密码已再次变更时拒绝覆盖；恢复后中心 JWT 需重新绑定。
- 当前 JWT 容器 /data/unified/kuma-bridge.jwt，mode600；不是可公开的配置样例。
- 252 Lucky、250 ESXi 属于历史关联设施，本次不得修改；需要时由所有者另行授权。

## 本地工作区与取证

- 原用户工作区 D:/codex-项目/clash：有其他未提交内容，不得 reset/clean。
- 0.2 工作树 D:/codex-项目/clash-unified-panel-20261028：有 3 个无关 dirty rule 文件，不得混入提交。
- 0.3 工作树 D:/codex-项目/clash-integrated-control-20261028。
- 私有取证 D:/codex-项目/clash-installer-20261026/reports/installer-20261026/integrated-control-1793135265。
- 本地 prod_runner.py 及 prod_integrated_*.py 在上述 reports/installer-20261026；可能含认证上下文/私有配置，不公开上传。
- 旧聊天 PTY/SSH 会话与本地 Git relay 不持久；新 AI 必须重新建立经授权连接，不能复制会话号当成有效连接。

## 安全恢复原则

1. 读取当前身份、挂载、镜像、Selector、Provider URL 和 Corefile SHA，和备份比较。
2. 先核实备份 SQLite integrity、配置可解析、镜像存在、控制台/SSH 备用通道。
3. 未接受切换由外部超时守卫恢复原镜像/Compose/精确旧状态。
4. 已接受后的回退必须保留用户后来合法 DNS/来源意图；遇到漂移拒绝覆盖并人工核对。
5. 不恢复陈旧账号数据库来替代当前密码，不打印 JWT/订阅原文。
6. 只删除明确归属本轮且标签和 ID 匹配的测试容器，不执行全局 prune。

历史 Corefile 基线：711 字节，SHA256 b56eeb5c70de928390675acbb8182330f369ad5f8144ef47090b89482471d11d。Windows 文本读取会转换换行，必须在容器对原文件字节做散列。

## 尚未完成的最终预演

从已提交代码构建最终镜像；把新鲜在线备份复制成独立 control/kuma/coredns/router 输入，使用 acceptance/isolated_lab.py layout/prepare/boot/verify。不得把生产订阅数据烘焙入镜像。隔离网络不映射宿主端口，浏览器需要独立临时隧道。测试 Kuma/DNS 的写入只针对副本。

最终记录镜像 SHA、源码 commit、rootfs lineage、各运行文件散列、保护状态前后对比和回退证据；未通过前不关闭生产 3101。

## 历史本地文件范围

[本地历史文件清单](local-history-inventory.json) 记录未自动上传的原工作区文本/脚本/报告的路径、大小与 SHA-256。它是定位索引，不是内容备份。原工作区含其他项目及秘密，不能直接 git add 全目录；需要原文时按清单向所有者索取并单独脱敏。当前 0.3 源码已完整保存在开发分支，不依赖这些旧脚本才能继续开发。
