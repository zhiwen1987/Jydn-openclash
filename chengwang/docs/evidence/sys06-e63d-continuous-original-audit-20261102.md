# FINAL — e63d continuous HTTPS 原件审计

结论：`ACCEPTED_LIMITED_SCOPE`。run `41439397849` attempt `1` 的 5 个原始 ZIP、严格 checker、31 个 HTTPS 响应、两次完成 Recovery、四命令 PIDFD 生命周期、六端口退出、source before/after 与 fresh 原件均通过。

- HEAD：`e63d006560b4c4c58b71f7e66b7f4d69299c07c5`；parent `4878dc77c77eae8eb56a6ad863bfe3c47d0176bf`；tree `57a069d416255c673344ec6f29a66ffde2faec43`。
- HTTP：31（200 x 26，201 x 5）；Recovery：2 x COMPLETED；format/go/attempt exit：0/0/0。
- 进程：4 个命令、16 个事件，每个均取得 PIDFD 并 WAIT_RETURNED=0。
- 端口：28411..28415 与 42013 均 CONNECTION_REFUSED。
- 原件集合：public 49 files，originals ZIP 57 members；producer/fresh/canonical-LF verification 均 871 bytes、SHA-256 `041becb8adc348f05dcea4bda952e0867e1ce1ec451bf04b11107a542c15dd09`。
- Windows CLI 通过语义检查但 stdout 仅因末尾 CRLF 为 872 bytes；该文件保留，不冒充 Linux CLI byte-equal。
- 一次下载前 `METADATA_FILE` 本地路径拼写失败已保留，未发生认证或下载。

范围不包含生产、完整私有 WAL 独立证明、互联网/业务、发布者签名或运行时兼容性。未读取 job logs/session/raw private logs，未运行本地 Go/gofmt/browser/server/SSH/生产。实际 reviewer model：`UNKNOWN`。
