# SYS07 组合源码集成与验收边界

本记录对应代码提交 `0be21a1b42c5c5400634e4ddbf4a5a0f157455e2`，代码树 `92d5d8650eb410ec97d750aff7a843bf42eac89a`。这是开发环境源码和纯 Python 检查结果，不是上线记录。

## 实际完成

- 集成 P207 v4 的源码集合与必跑集合分离、完整工作流指纹和历史身份检查。
- 集成 A1a existing-only 只读证据快照及 nativefs 固定来源镜像；尚无产品调用者，未选定生产读取限额，也不代表完整 A1 发布和激活已实现。
- 集成联合场景的有界启动诊断、实际步骤结果约束和故障注入检查；独立诊断文件自身不具备可信运行证明。
- 集成 Go 测试时间线、信号处理和有界公开目录校验；保留 180 秒 Go 预算和 120 秒 profile 计时，不宣称解决了旧超时根因。
- 修复两个 Git 替换对照测试继承环境的问题：仅合成夹具的“不受保护”子进程移除环境标志，产品 Git 防替换保护不变。
- 41 个源码后像经组合冻结与两个独立切片复核。最新源码检查通过：842 module、21 fixture、545 source tops、528 required tops、S92/Q80、38 changed-Go、foundation 689。联合来源契约 853 条，由当前 HEAD 实际生成并与跟踪文件逐字一致。

## 纯 Python 验收与真实失败

同一代码提交的原运行中，P207 82、bootstrap 82、pin 47、evidence 29、timeline 38、capacity 5，共 283 项通过。nativefs 原进程实际运行 7 项并成功，但外部 harness 的单行匹配漏计一项，且错误要求 OK 必须为输出末尾，导致原汇总失败；原汇总不修改、不改绿。

修订的外部 harness 使用独立结构化 unittest 结果，要求 loaded、started、success 名单与源码 AST 精确相等，testsRun 正确、失败和跳过等分类为空、进程退出为零。fresh nativefs 7 项及 7 个计数反例通过，独立复跑再次通过。因此可组合为 283 项原记录加 fresh 7 项，不能称为一次完整 290 项运行，更不是 290 项 Go 测试。

更早的两个 timeline 对照夹具失败及后续修复证据同样保留。

## 可定位证据

完整路径、SHA256 和限制见 [组合证据索引](evidence/sys07-combined-source-root-20261103.json)。历史 P207 的 491 项来源检查保留为历史截点，不替代本次 528 项的实际 Go 运行验收。

## 未完成

此代码提交尚未取得自己的隔离 Linux Go、gofmt、official selection、source/fresh、联合 B0/J1/R2、foundation/capacity 时间线或 31 步 HTTPS 验收原件。actualfs 标签测试、真实 Linux UID、文件系统耐久、完整 A1 发布/激活、产品 authority/executor、企业功能和真实业务验收均未完成。旧提交的通过不迁移到新提交。

生产、原项目 main、Registry、路由器和现网 DNS 均未改动。Hy-Memory 工具不可用，未声称读取或写入共享记忆。
