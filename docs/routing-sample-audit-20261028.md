# 分流样本域名阶段审计（2026-10-28）

- 样本：2567 条唯一上游规则域名样本；严格计分 2264 条；政策待确认 303 条。
- 严格计分集的政策一致率：1991/2264 = 87.942%。期望大多由固定分类快照和仓库政策映射推导，并非独立网络事实。
- 人工政策锚点：14/18；政策待确认样本中实际一致 262、不一致 41。
- 模拟边界：固定上游快照、仅域名匹配；不连接设备，不覆盖 IP、端口、进程或复杂 classical 条件，也不声称实时网络封锁状态。
- `actual` 是规则首次命中的目标策略组，不是该组当前选择的节点或实际出口；本审计没有读取运行时选择。
- 完整错配、首个命中规则及来源成员关系见 `reports/routing-sample-audit.json`。

## 错配分类

- 其他错配：4
- 国内策略域名却进入非 DIRECT 目标：12
- 应走业务组却被抢先：297
- 需代理政策域名却命中 DIRECT：1

## 已知政策锚点

- `52ojk.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `6ta.net`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `6wz.net`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `amd.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `developer.amd.com.cn`：期望 `DIRECT`，实际 `DIRECT`，首命中第 90 行 `developer.amd.com.cn`。
- `drvceo.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 51 行 `external-direct`。
- `fonts.googleapis.com`：期望 `🔎 谷歌服务（Google）`，实际 `DIRECT`，首命中第 64 行 `google-cn`。
- `futunn.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `hhyunerp.com`：期望 `DIRECT`，实际 `🐟 漏网之鱼`，首命中第 228 行 `None`。
- `iq.com`：期望 `🎞️ 海外影音`，实际 `DIRECT`，首命中第 51 行 `external-direct`。
- `kefu.me`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `lla8.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `mmstat.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `moomoo.com`：期望 `🌍 境外网站`，实际 `🌍 境外网站`，首命中第 109 行 `mygw.yaml`。
- `snssdk.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 116 行 `direct.yaml`。
- `spdb.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 102 行 `bank-cn.yaml`。
- `sysceo.com`：期望 `DIRECT`，实际 `DIRECT`，首命中第 86 行 `sysceo.com`。
- `www.hhyunerp.com`：期望 `DIRECT`，实际 `🐟 漏网之鱼`，首命中第 228 行 `None`。

## 修复清单

### 可在现有规则文件修复

- `hhyunerp.com` 及子域当前落入 FINAL；有独立用户政策证据，可在既有 `rules/direct.yaml` 用一个后缀条目修复。

### 需要模板或顺序另行授权

- `fonts.googleapis.com` 被更早 `google-cn` 命中，`iq.com` 被更早第三方直连命中；修改后置规则文件不能覆盖。
- 业务组被抢先共 297 条；完整域名、期望、实际目标及首命中规则在 JSON 中，不能机械加入后置规则。
- 游戏被海外影音抢先需要修改运行配置模板；本次仅记录，未经单独批准不修改。

### 需要用户决定

- 政策冲突待确认 303 条，其中目标不一致 41 条；广告与业务、国内分类与海外业务等重叠不自动视为代码缺陷。
- 国内政策非 DIRECT 目标共 12 条；除已有独立政策证据外不自动加入直连。
- DNS 覆写键属于设备配置问题，本次仅记录，未经单独批准不修改。

## 固定来源获取与许可（本轮修订）

- 不再分发上游原文快照包。按 manifest 固定 commit 联网拉取并验证 SHA-256，原文只进入被忽略的 `.cache/routing-audit/`；哈希不符、下载失败或缓存损坏即停止。
- 来源为 MetaCubeX/meta-rules-dat（项目声明 GPL-3.0）和 Aethersailor/Custom_OpenClash_Rules（原创内容 CC BY-SA 4.0，第三方材料各自许可），具体固定提交与归属见 [NOTICE](../tests/routing-sources/NOTICE.md)。样本和匹配结果不是上游文件原文。
- 同一 2567 条样本、同一上游字节：原基线 `f83ff23` 为 1991/2264 = **87.942%**、人工锚点 **14/18**；合入 #27 后的 main `4e87414` 为 1993/2264 = **88.030%**、人工锚点 **16/18**。严格分母及政策待确认样本口径不变。
- 这是固定分类政策的域名阶段一致率，不是现网准确率。以上保持历史基线用于对照，不把已合入的直连修复重新当作未修故障。
