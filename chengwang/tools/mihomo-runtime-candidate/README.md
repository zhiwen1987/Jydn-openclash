# SYS06 Mihomo：离线候选 pin 消费工具

这是隔离开发工具，不是正式内核发行、运行兼容证明、签名批准或生产部署。当前只实现字节消费与独立验收；任何真实内核下载、展开、执行、API 操作和发布均须另行授权及验收。不会自行联网或运行所读文件。

固定候选来自 [MetaCubeX/mihomo v1.19.32 官方资产](https://github.com/MetaCubeX/mihomo/releases/expanded_assets/v1.19.32)：`mihomo-linux-amd64-v1-v1.19.32.gz`，发布页 SHA256 `306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc`；上游源码为 `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`。官方元数据研究 manifest SHA 为 `76b194ad7183cb661ad2deef164f30f9d8a260ddbc823e53b7760253a71bc7dc`。这些是元数据完整性依据，不是发行二进制签名；上游 Git commit 的 verified 标记也不能替代二进制签名。

`pin.json` 的精确压缩大小、实际 ELF 大小与 ELF SHA 仍为 `null`，不能编造或以四舍五入显示值填充。实际尺寸/摘要只在成功消费原字节后进入新的 receipt，历史 pin 不回填已执行。`--source-commit` 是本项目待验源码的完整 commit，绝不是上述上游 commit。

## 固定接口与输出闭集

仅当这五个工具文件已在本项目同一 commit 中、宿主文件与 Git 原 blob 逐字相同且 HEAD 对应 `--source-commit` 时允许完整 CLI。工具自身必须从 `--repo` 对应文件运行，不能换成另一份脚本而声称绑定了源。只查五个文件，不枚举或 clone 整个仓库。未提交的当前开发文件不能冒称真实源绑定 CLI 已通过。

以下仅是后续获准隔离 Linux POSIX 环境的接口说明，本说明不构成执行授权：

```text
python3 -B chengwang/tools/mihomo-runtime-candidate/consume_pin.py \
  --archive /owned/original.gz --repo /existing/project \
  --source-commit <本项目完整40位commit> --output /owned/new-evidence

python3 -B chengwang/tools/mihomo-runtime-candidate/check_consumption.py \
  --archive /owned/original.gz --repo /existing/project \
  --source-commit <同一本项目commit> --evidence /owned/new-evidence \
  --report /owned/new-independent.json
```

成功输出目录必须是原先不存在的新目录（0700），闭集仅：

- `mihomo`：实际解压原字节、regular/nlink1、0500。只是可执行权限，不代表运行过。
- `consumption.json`：0400、canonical JSON＋LF；含实际 gzip/ELF 大小和摘要、ELF header/程序段事实、五工具 Git 源绑定。`runtimeExecuted`、`runtimeCompatibilityProven`、`businessAvailabilityProven`、`publisherSignatureProven`、`productionApproved`、`production` 均为 false。

独立 checker 不 import producer。它从同一个原 gzip 重新解析 RFC1952 header/raw DEFLATE/sole trailer，校对 CRC/ISIZE、单成员完整性、实际 ELF header/程序段，并重新读取实际 `mihomo` 的全部字节及 POSIX 模式，与独立重建的 canonical receipt 逐字节比较。`--report` 必须在 evidence 闭集外且原先不存在；输出为经独立重算后与 producer receipt 逐字一致的 JSON。stdout 仅固定通过/拒绝提示，不输出任意原字节或异常内容。

## 拒绝条件与边界

压缩最多64MiB、展开最多128MiB；压缩 SHA 必须精确匹配上述发布页 pin，然后才解压。拒绝拼接成员、任何尾随字节（含零）、截断、CRC/ISIZE 坏、超限、非 ELF64/little-endian/AMD64/EXEC 或 DYN、越界程序段和未落在可执行 file-backed LOAD 中的入口。输入及输出必须 regular/nlink1、无 symlink/reparse 路径，读取前后 lstat/fstat 身份和同 API ctime 稳定；成功输出用 exclusive 创建且读回，既有目标不覆盖。失败后的本次私有目录可能保留未完成文件，只供诊断，不能当成功 receipt 或重用为新输出。

POSIX 权限无法在 Windows 上证明，完整消费/验收拒绝非 POSIX。Windows 只运行小型 synthetic gzip/ELF 的纯 CPU 单元测试；其中 mock Git 明确使用假 project commit，不称为完整 CLI 源绑定成功。不得在本机下载/执行真实候选来凑验收。

当前合成名单冻结47项，排序方法名以 LF 连接、不附尾 LF 的 SHA256 为 `390ff9bf1c63f9d586de54df624d81fedbaa2258d0e82f39e7108e1063c7c6fc`。除 gzip/ELF/文件和源绑定反例，还独立拒绝 receipt 的尺寸/摘要/源 commit/权限/执行标记/未知字段/重复字段/非 canonical 修改。原38项首轮日志与最终47项日志应分别保留，不能将新增测试追溯算作原首轮结果。

可信独占工作目录下的稳定 stat 读回不是抗恶意同 UID 的文件系统快照。该消费目录的 owner/mode 也不证明 namespace 隔离；后续执行 supervisor 仍必须独立复制到 root-owned 只读 bundle，并校对实际进程、网络/权限边界、真实配置测试/API/流量/恢复/退出。未校验发布者二进制签名、CPU 指令兼容、动态库依赖、运行版本、业务可达性或生产批准；不会把 parse 通过或 HTTP 204 当成上线与健康。
