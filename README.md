# Jydn OpenClash 规则与转换模板

本仓库只维护 OpenClash/Subconverter 的规则、模板、自定义分组、配置覆写及其构建校验工具。

管理中心、订阅与节点控制、Docker/安装器和系统交接资料已独立到 [clash-center 私有项目](https://github.com/zhiwen1987/clash-center)，需要仓库访问权限。本仓库不部署或操作生产服务。

## 使用地址

| 内容 | 地址 |
|---|---|
| 现有转换模板（保留兼容） | `https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash/refs/heads/main/metafenliu.ini` |
| 独立公开模板 | `https://raw.githubusercontent.com/zhiwen1987/Jydn-openclash-rules/refs/heads/main/metafenliu.ini` |
| 当前规则文件 | [rules/](rules/) |
| 可选覆写和配置示例 | [modules/](modules/) |

不要把订阅地址、Token、节点凭据或私有配置提交到仓库。DNS 覆写属于行为变更，使用前须独立审核；源码更新不代表设备已加载。

## 文件分工

- `upstream/metafenliu.ini`：上游模板输入。
- `custom/`：本项目自定义规则、分组与菜单输入。
- `rules/`：域名/IP 规则 payload。
- `modules/`：可选 YAML 覆写、规则示例和生成的分组目录。
- `scripts/`：模板生成、规则校验和必要配置编译器。
- `metafenliu.ini`：生成的转换模板，不应绕过源输入长期手改。

维护步骤见[规则与模板维护](docs/template-maintenance.zh-CN.md)，检查范围见[校验与恢复](docs/rules-validation.zh-CN.md)。

固定版本域名样本审计见[分流样本报告](docs/routing-sample-audit-20261028.md)。工具按 manifest 固定提交联网获取并校验上游文件，本地缓存不入库；报告重放规则目标，不代表设备当前出口或网站实时可用性。

## 自动更新

`Build OpenClash Template` 保留模板构建、校验和生成产物提交；`Publish public OpenClash rules` 在合格构建后，使用原有专用发布凭据，把严格允许的通用规则和模板同步到 [Jydn-openclash-rules](https://github.com/zhiwen1987/Jydn-openclash-rules)。单个任务失败不会删除上个公开版本。

现场专用 WebRTC 内容在公开规则导出中仍为空占位；本仓库原有规则文件继续保留原内容。本次目录清理不修改任何设备的规则 URL、DNS、节点或业务选择。

## 历史范围

当前分支移除 Clash Center 源码和交接资料，Git 历史没有重写。删除当前文件不等于擦除历史提交；历史系统运维资料不再作为本仓库的使用入口。
