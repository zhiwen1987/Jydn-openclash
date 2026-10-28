# 规则与模板维护

## 构建

```sh
python3 scripts/check_rules_repository.py
python3 scripts/build.py
python3 scripts/validate.py
ruby scripts/test_patch_runtime_groups.rb
ruby scripts/test_routing_controls.rb
ruby scripts/test_strict_custom.rb
python3 scripts/test_publish_public_rules.py
```

建议使用与 CI 相同的 Linux、Python 3 和 Ruby/YAML。上述脚本只校验/生成本地文件，不需要 SSH、生产账号或运行中的 Clash Center。

## 修改位置

业务规则与分组维护 `custom/rules.ini`、`custom/groups.ini`，对应规则 payload 放在 `rules/`；上游输入在 `upstream/metafenliu.ini`。运行 build 后审阅生成的 `metafenliu.ini`、`modules/openclash-dns-privacy-override.yaml`、`modules/openclash-business-group-catalog.json`。

规则先后顺序是实际匹配语义的一部分；核对国内、海外、私网和用户例外，避免用共享 CDN 或整个 ASN 粗暴替代业务域名。模板、生成文件、设备活动配置与真实新连接的匹配结果是不同层次，不能把生成成功当作生产已加载。

`strict_custom.rb` 是纯配置编译器，空/无效私有输入保持 REJECT；`routing_controls.rb` 和 `patch_runtime_groups.rb` 维护配置菜单及空组语义。相关 Shell hook 只是配置覆写适配，不包含中心的 HTTP、监控或节点发布服务。部署这些覆写属于另外的设备变更任务。

## 公开导出

```sh
python3 scripts/publish_public_rules.py --output /tmp/jydn-public-rules
```

输出目录必须尚不存在。导出只允许 README、转换模板、17 个模板引用规则和额外的 smarthome-direct 规则；不会复制运行代码或交接资料。现场 WebRTC 规则导出为空占位，其他非通用私网、凭据 URL、Token、私钥或非 payload YAML 默认拒绝。

保持工作流名称 `Build OpenClash Template`，因为公开发布器按这个名称监听成功构建。不要擅自替换模板中的源仓库 URL：校验器和发布器共同维护 URL 转换契约；实际生产迁移应作为单独任务执行。
