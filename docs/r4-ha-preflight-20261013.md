# R4-HA 预发布验收记录（2026-10-13）

## 结论

第二阶段预发布门禁通过。R4-HA 已作为独立候选文件上传并完成静态、运行期模拟和 Mihomo 内核测试；生产仍运行 R3，没有切换活动配置，也没有重启 OpenClash。

## 生产基线

- 活动配置：`/etc/openclash/config/精准稳定-v1-r3.yaml`
- OpenClash：`0.48.002`
- Mihomo：`Meta alpha-smart-gdaf3ad0 linux amd64`
- 操作前后核心 PID：`28250`
- R3 源配置与备份内文件哈希一致：是

## 双份备份

- 旁路由：`/root/openclash-backups/20261013-043512-r4-preflight`
- Windows：`D:\OpenClash-Backups\20261013-043512-r4-preflight`
- 快照：`openclash-r3-snapshot.tar.gz`
- 快照 SHA-256：`C529BC2517D66F0EB44C0B5E7A8A6627D9F71F14070BF3D95E2C44A0F427BEDA`

快照包含活动 R3 源文件和运行文件、OpenClash UCI、覆写目录、自定义脚本、R3 选择状态数据库以及操作前日志。Windows 副本下载后与旁路由端校验值一致。

## R4 候选

- 旁路由候选：`/etc/openclash/config/精准稳定-v1-r4-ha.yaml`
- Windows 副本：`D:\OpenClash-Backups\20261013-043512-r4-preflight\精准稳定-v1-r4-ha.yaml`
- SHA-256：`7F875896B3193B97B3C3BA004F119A6CEF8768CA1C85AE0C79448BF704CA778D`
- 组数：99
- 业务专用池：4
- 活动状态：未启用

## 已通过门禁

1. 仓库生成结果可重复，静态验证通过。
2. 当前 Mihomo 对原始候选执行配置测试成功。
3. 运行期空组过滤 Ruby 测试通过。
4. 使用新目录模拟空组过滤和 Zashboard 排序后仍为 99 个组。
5. 模拟运行 YAML 再次通过当前 Mihomo 配置测试。
6. ChatGPT、Claude、Gemini 默认第一项为各自专用池，第二项保留 `🧠 人工智能`。
7. Netflix 默认第一项为专用池，第二项保留原 `🎬 流媒体节点`。
8. 运行期 provider 缓存缺失数为 0，17 个基础可选节点组均可用。
9. 候选测试后活动路径仍指向 R3，核心 PID 未变化，日志未出现新增启动错误。

## 现网回归检查

所有 HTTP 请求均通过当前 R3 的本机认证代理执行：

| 检查项 | 结果 |
| --- | ---: |
| 百度 | 200 |
| AMD 中国 TokenFactory | 200 |
| 涂鸦中国 | 200 |
| ChatGPT trace | 200 |
| Claude favicon | 200 |
| Gemini | 200 |
| Netflix | 200 |
| Google generate_204 | 204 |

AMD 中国和 Gemini 的本机 DNS 查询均正常返回，OpenClash 日志未发现新增 `error`、`fatal`、`panic`、配置错误或启动失败。

## 恢复位置与方法

本阶段没有切换，因此正常情况下不需要恢复。如果候选文件需要撤销，只删除独立候选即可，R3 不受影响。

未来切换后如需恢复，应先确认备份目录和压缩包校验值，再恢复快照中的 R3 文件与 UCI，活动路径明确设回：

```text
/etc/openclash/config/精准稳定-v1-r3.yaml
```

恢复后必须重新验证 DNS、国内直连、AMD 中国、涂鸦、ChatGPT、Gemini 和 Google 204；只看到进程启动不算恢复成功。

## 尚未执行

- 未把 R4 设为活动配置。
- 未重启 OpenClash。
- 未启用自动控制器或自动修复。
- 未执行生产灰度观察和自动回滚演练。
- 未把本分支推送到 GitHub。
