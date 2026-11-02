# 正常业务二进制联测：已核源码前提

源码身份：736bfdd1f8182e958cea26987f85683e2c6aee39。本页只证明源码事实，未执行服务或真实联测。

1. `internal/serverruntime/runtime.go` 在同一运行时装配 subscriptions、refresh、普通 controller observation 和 live overview；`cmd/server/main.go` 通过 RunWith 使用环境配置。不得假造不存在的业务命令行参数。
2. `internal/serverruntime/subscription_config.go` 要求 refresh 开启时同时有 writes、绝对 policy 文件、合法 machine identity；subscriptions 还要求 TLS、identity 与合法作用域。
3. `internal/subscriptionctl/refresh.go` 的 ConfigureRefresh 在启动阶段读取 policy bindings，并逐项要求库存来源已经存在；machine principal 的角色与来源授权集合必须准确匹配。真实 E2E 不能用不存在来源直接启动 worker。
4. 计划启动顺序应先以 refresh 关闭的同一 binary，通过真实授权 API 建立来源和批准状态，正常退出；再以相同 data dir 开启 refresh，验证后台 RunRefresh 与 HTTP 读回及重启。此处为待独审方案，API/批准流程仍由方案代理逐项确认；不得直接 seed WAL 代替业务。
5. RunRefresh 的固定轮询间隔为5秒；场景必须有界观察实际状态，不能改产品时钟、加速测试钩子或假造worker成功。
6. 现有 remote_fetch_fixture.py/lab_contract.py 通过私有无出口 netns 的 lo 地址8.8.4.4:443及DoT127.0.0.1:1853，以正常CA/SAN测试SSRF安全路径；不是访问公共Google服务，也不是允许loopback绕过。
7. 旧wire fixture固定180秒、12事件/3连接，不能擅自让旧checker接纳更多连接来拼新场景。新业务场景需要独立可验证的fixture契约与证据投影。
8. lifecycle lab配置与上述业务组合互斥；保持现有拒绝门。若未来要统一写执行权，需独立executor/authority设计，不能只删除配置检查。

下一交付：正常业务scene的具体API矩阵、TLS/identity/policy fixture、真实binary来源绑定、worker与重启事实、错误/foreign RBAC、只读overview投影、正常进程关闭、端口/存储/host前后核验与独立fresh reader。未完成前不声称全系统业务闭环。
