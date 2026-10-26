# 备份与恢复

## 备份在哪里

- Docker 主机：`/opt/clash-stack/<站点>/backups/<事务号>/`。包含原 Compose、容器私有描述及挂载数据快照；SQLite 使用在线 backup API 并进行完整性检查。
- 旁路由：`/root/clash-stack-backups/<站点>/<事务号>/`。包含原 UCI、覆写钩子、相关配置、选择状态，以及本次更改的规则数据文件。
- 当前事务：分别在两端站点目录的 `transaction.json`；验收通过的版本在 `state.json`。日志和备份可能包含密钥，均限制权限，不要直接公开。

这些是应用恢复材料，不是 ESXi 整机快照。多个数据库分别在线备份，不承诺整个网络同一时刻的事务一致性。

## 常规回退

在安装包目录执行 `start.ps1 restore --profile sites/home.json`，或 Linux 下 `sh install.sh restore --profile sites/home.json`。先恢复旁路由，再恢复中心服务；保留运行期间新增的数据，不自动覆盖数据库。Kuma 跨版本升级会被预先拒绝，避免用旧程序强行读取不兼容数据库。

检测到新的人工文件修改或容器身份变化时，恢复会拒绝覆盖并要求人工核对。不要绕过检查强行覆盖生产配置。

## 安装途中断线

中心端使用独立的 systemd 定时恢复任务，旁路由使用独立 procd 恢复任务，均不依赖正在安装的容器或操作端。未验收事务约 10 分钟后尝试恢复；操作端异常时也会立即请求回退。设备断电期间守护无法执行，重启后以目标机实际事务记录为准，不能承诺两分钟恢复上网。

如果安装器无法连接，可从设备控制台检查：

```sh
# Docker 主机：请求恢复当前未验收事务
sudo python3 /opt/clash-stack/home/guard-agent.py /opt/clash-stack/home/guard-request.json

# 旁路由：检查当前事务和恢复守护
ls /etc/openclash/custom/clash-stack-home/transaction.json
/etc/init.d/clash-stack-rollback-home status
```

将 `home` 换成实际站点名。旁路由 guard-agent 的常规启动会等待事务截止时间；需立即恢复时优先重新运行安装包的 restore 命令。不要执行来历不明的清空、防火墙重置或整机恢复命令。

最终确认按中心、旁路由的顺序执行，避免已解除旁路由保护而中心随后被撤销。两台设备不是原子提交：操作端若在两次确认之间退出，中心可能保留新版本而旁路由自行恢复。请以两端 state/transaction 记录为准，再运行 verify 或 restore。网络地址、端口和接入档案变化会拒绝借普通升级迁移。

收据中 `cleanup_warnings` 表示定时任务清理未完成；它与程序/配置是否已恢复分别记录。此时应核对列出的本站点任务和事务记录，不能把清理警告当成所有步骤都已通过。

## 回退不会做的事情

恢复保留数据库、自建节点、历史日志和备份；不会自动重置管理员、恢复 Windows DNS、修改爱快下一跳或操作 Lucky。主路由的接入更改应由其自己的配置备份恢复。
