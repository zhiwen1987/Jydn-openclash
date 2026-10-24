# SYS-01／23：能力真值的真实浏览器验收前置

状态：前置代码正在集成；完整capability_truth场景、驱动、独立checker及四组producer／fresh均未实现。不能把本页设计、源审查或纯CPU结果记为真实浏览器通过。基线为已推送的1d4b59d；本页所述后续代码在未取得新源码CI前均属候选。

后续实际结果：918bc36的2项DemoModeTruth已实际通过；306整体仍因旧快照错误提示断言失败，不能记为前端或镜像全绿。订阅八组真实producer与fresh成功、探针两引擎原件14CLI复算通过，均不能补算本专项能力页场景已经实现或可跑。下文设计和实施前“尚未运行”按各自时间保留；最新错误接线修正见[实际记录](P2-SNAPSHOT-FEEDBACK-CORRECTION.md)。

## 已定位并处理的产品缺口

真实服务可在candidate模式提供demo来源快照；两者含义不同。原DemoOverview却硬编码Shadow和全局影子只读暗示，顶栏又显示实际candidate，造成同页矛盾。这是源码确定的缺陷，尚无本专项真实截图证明它已修复。

后续候选改为显示snapshot.mode，说明“总览仅展示数据边界；执行权限以服务端授权为准”，并将标签限定为“总览只读”。新增2项DemoModeTruth组件测试，保留旧304源码及名单，下一前端要求306项／14文件，**尚未运行**。新2项fullName排序LF无尾LF摘要为`b3438ab865c53ffdf53d9d104f8fb31860d471c613f479d8f7ff88d46ae43df1`；mock只验证组件防御行为，不冒充真实服务。

## 中性生命周期的第一步

现有订阅supervisor的场景配置、准备、读回及导出与生命周期交织，不能直接传入新场景，也不能复制整份runner制造第二套维护分支。第一步只机械抽出三个可复用leaf：

- append_process_records：按原任务顺序原位追加；后续任务失败时，前面真实进程记录仍保留。
- terminate_children：保原node／server／wire顺序、forced计数、5秒terminate等待及3秒kill等待，异常继续传播。
- wait_namespace：保225秒原等待及5／3秒终止流程，只返回原timed_out，不返回伪造成功标志。

旧四场景的prepare／inner／wait_server／export／env／main入口、argv、schema、PUBLIC和成功出口不改。SOURCE_FILES仅末尾追加新helper，launcher原索引1保持。新helper不在import阶段启动产品进程或执行应用I/O。

这是CI收集工具的可复用前置，并非产品自动修复执行器；更不是已经完成prepare_scene_inputs／supervise_scene／export_scene_evidence。新增19项使用假进程对象的CPU反例，不能代替真实Linux权限、进程退出、旧四场景双引擎和fresh兼容验收。

实际CPU结果为新19＋旧186共205个不同用例通过，零skip；最终注释收窄后19复跑通过，不重复累计。根独立执行本候选workflow的新19精确名单／start／pass门，实际exit 0，另有19个Bash块及offline gate语法检查，记录摘要`0553b525791b4480e425597effabbc323ad2f650709560881770897d07079f17`。四个未改旧checker对新增helper的4正／12反绑定检查符合预期，但该层Git访问使用mock，不是实际候选Git／进程运行证明。

三个搬移块经显式变量代换后AST与原块相同；将旧wrapper恢复三块并移除loader／source追加后，完整模块AST与原版本一致。保留部分records是特意检查的失败语义，不能改成返回新list后赋值而丢失中间证据。完整真实8矩阵及fresh仍须新CI，不由机械等价证明取代。

## 下一真实矩阵

| Profile | 真实构造 | 可以证明 | 不可据此推导 |
| --- | --- | --- | --- |
| default | 正式产品server及Vite产物、普通CA TLS；无身份／订阅／Mihomo／Probe配置，写门关闭 | 按实际匿名API展示默认能力、demo总览边界及内核规划；刷新发出独立新请求 | 已认证、可写、生产就绪或真实业务健康 |
| backend_configured | 合法固定scope、临时真实身份文件、订阅存储启用但写门关闭；Mihomo适配器配置隔离回环未监听端点 | 区分本地实现、已配置与设计／受阻；不能把配置显示为连接成功 | 实际上游可达、当前用户授权或live快照provider |

每profile分别使用现有固定版本Chrome/CDP与Playwright，共四个producer；每份原件另由无运行服务fresh job独立重算并逐字节比较。复用正常TLS、既有隔离和固定依赖机制，不改原订阅／Probe成功门、八错误计数或等待预算。

真实路径拟为总览桌面→内核桌面→能力首读→能力原生刷新→能力移动→内核移动→总览移动，七个DOM checkpoint及六张PNG。浏览器真实GET为一份snapshot、两份capabilities；若另有readiness请求，必须单独命名计数。不得注入响应、替换fetch、改React state或新增测试专用假API。

独立checker必须从原始capture自行解析schema，重算每个实际条目、domain顺序、状态映射、summary和证据／限制全文，并与DOM逐项对应；不得导入producer判定函数或相信passed=true。当前registry有18项源定义，但状态取真实配置和证据，不硬编码每profile成功总数。尤其operation能力还依赖evidence有效，不能从identity存在推导；local_evidence_chain也不能填造新鲜状态。

## 明确保留的未构造项

当前server总是seedSnapshot且dataSource为demo。因此上述矩阵能验隐藏示例值，不能验live分支、真实设备库存、完整业务分流或DNS健康。正常API也不能可靠构造10秒截止、卸载中止、迟到响应或真实unknown／timeout；这些必须另做受控真实生命周期场景，不能用mock替代。尚缺完整公件exact-key schema、DOM投影及prepare／supervise／export接线，故合同候选没有被冒称为可执行场景。

## 已有订阅截图的补充

5f UI的8份producer共16张原PNG已逐图查看并核摘要，可见首屏中文清楚、无明显遮挡或横向文字裁切。存在14份唯一字节：三个Playwright移动首屏相同，业务差异在视口下方；不能把16文件当16种不同结果画面，也不能据相同摘要推定损坏。

负交接桌面实际checkpoint是unknown_failed的明确拒绝／旧数据暂停，移动是final_mobile的历史回执摘要，两者不是同态。“操作未确认”统一标题仅记P2文案建议，不据此判逻辑失败。八张移动图未覆盖下方候选、批准／抓取／准入按钮和完整回执，不能算完整移动业务视觉验收。见[逐图机器摘要](evidence/p2-5f17544-visual-followup.json)。

生产、main、正式Registry及现网路由／DNS均未改。完整系统剩余工作仍以[任务台账](LIVE-TASKS.md)和原功能基线为准。
