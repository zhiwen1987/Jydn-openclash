ENV['MANAGED_SOURCES_ROUTER_LIBRARY'] = '1'
require 'minitest/autorun'
require 'tmpdir'
require_relative '../agents/managed_sources_router'

class ManagedSourcesRouterTest < Minitest::Test
  M = ManagedSourcesRouter

  def with_stubs(stubs)
    singleton = M.singleton_class
    originals = {}
    stubs.each do |name, replacement|
      originals[name] = M.method(name)
      singleton.send(:remove_method, name)
      singleton.send(:define_method, name) do |*args, **kwargs, &block|
        replacement.respond_to?(:call) ? replacement.call(*args, **kwargs, &block) : replacement
      end
    end
    yield
  ensure
    originals&.each do |name, original|
      singleton.send(:remove_method, name)
      singleton.send(:define_method, name, original)
    end
  end

  def settings
    { 'schema' => 1, 'server_host' => '10.88.0.249', 'server_port' => 3103,
      'publish_token' => 'a' * 64, 'api_port' => 9090, 'api_secret' => 'private' }
  end

  def fixture
    groups = M::AUTO_GROUPS.each_with_index.map do |name, index|
      { 'name' => name, 'type' => 'url-test',
        'use' => M::LEGACY_PUBLIC_PROVIDERS.dup,
        'filter' => 'country-filter-' + index.to_s,
        'proxies' => ['REJECT'], 'interval' => 300 }
    end
    groups += [
      { 'name' => '🧭 手动选择', 'type' => 'select', 'use' => M::LEGACY_PUBLIC_PROVIDERS.dup, 'proxies' => ['DIRECT'] },
      { 'name' => '⚫ Grok 稳定节点池', 'type' => 'select', 'use' => ['Provider_BFFC55'], 'proxies' => ['REJECT'] },
      { 'name' => '🔐 自定义节点', 'type' => 'select',
        'use' => M::LEGACY_PUBLIC_PROVIDERS + ['Local_Custom'], 'filter' => 'all-valid-nodes', 'proxies' => ['REJECT'] },
      { 'name' => '🧪 节点能力检测', 'type' => 'select',
        'use' => ['Provider_BFFC55', 'Provider_7CAD88', 'Local_Custom'], 'proxies' => ['REJECT'] },
      { 'name' => '🤖 ChatGPT 专用节点池', 'type' => 'url-test', 'use' => M::LEGACY_PUBLIC_PROVIDERS.dup,
        'filter' => 'verified-ai-only', 'proxies' => ['REJECT'] }
    ]
    { 'mode' => 'rule', 'dns' => { 'enable' => true, 'nameserver' => ['127.0.0.1'] },
      'proxy-providers' => {
        'Provider_BFFC55' => { 'type' => 'http', 'url' => 'https://legacy-one.invalid/a', 'path' => './proxy_provider/one.yaml' },
        'Provider_7CAD88' => { 'type' => 'http', 'url' => 'https://legacy-two.invalid/b', 'path' => './proxy_provider/two.yaml' },
        'Local_Custom' => { 'type' => 'file', 'path' => './proxy_provider/local.yaml' }
      },
      'proxy-groups' => groups,
      'rules' => ['DOMAIN-SUFFIX,cn,DIRECT', 'MATCH,🧭 手动选择'] }
  end

  def test_patch_is_exactly_one_provider_and_exact_ordinary_groups
    before = fixture
    after = M.patch_document(before, settings)
    assert_equal before, M.strip_managed_auto(after)
    assert_equal before['dns'], after['dns']
    assert_equal before['rules'], after['rules']
    assert_equal before['proxy-providers'], after['proxy-providers'].reject { |name, _| name == M::PROVIDER }
    expected = M::CONSUMER_GROUPS.sort
    actual = after['proxy-groups'].select { |group| Array(group['use']).include?(M::PROVIDER) }.map { |group| group['name'] }.sort
    assert_equal expected, actual
    assert_includes after['proxy-groups'].find { |group| group['name'] == '🧭 手动选择' }['use'], M::PROVIDER
    custom = after['proxy-groups'].find { |group| group['name'] == '🔐 自定义节点' }
    assert_includes custom['use'], M::PROVIDER
    assert_equal ['REJECT'], custom['proxies']
    assert_equal 'all-valid-nodes', custom['filter']
    refute_includes after['proxy-groups'].find { |group| group['name'] == '⚫ Grok 稳定节点池' }['use'], M::PROVIDER
    refute_includes after['proxy-groups'].find { |group| group['name'] == '🤖 ChatGPT 专用节点池' }['use'], M::PROVIDER
  end

  def test_country_filters_and_all_original_group_options_are_unchanged
    before = fixture
    after = M.patch_document(before, settings)
    before['proxy-groups'].each do |original|
      patched = after['proxy-groups'].find { |group| group['name'] == original['name'] }
      original.each do |key, value|
        next if key == 'use' && M::CONSUMER_GROUPS.include?(original['name'])
        assert_equal value, patched[key], "changed #{original['name']} #{key}"
      end
      if M::CONSUMER_GROUPS.include?(original['name'])
        assert_equal original['use'] + [M::PROVIDER], patched['use']
      end
    end
  end

  def test_provider_contract_is_fixed_and_health_check_is_disabled
    provider = M.provider_definition(settings)
    assert_equal 'http', provider['type']
    assert_equal './proxy_provider/Managed_Auto.yaml', provider['path']
    assert_equal 3600, provider['interval']
    assert_equal({ 'enable' => false }, provider['health-check'])
    assert_match(%r{\Ahttp://10\.88\.0\.249:3103/providers/Managed_Auto\.yaml\?token=}, provider['url'])
  end

  def test_candidate_is_rejected_in_provider_group_manifest_or_proxy
    variants = []
    a = fixture; a['proxy-providers']['Managed_Candidate'] = { 'type' => 'http' }; variants << a
    b = fixture; b['proxy-groups'][0]['use'] << 'Managed_Candidate'; variants << b
    c = fixture; c['manifest'] = { 'role' => 'Managed_Candidate' }; variants << c
    d = fixture; d['proxies'] = [{ 'name' => '__STACK_EMPTY_MANAGED_CANDIDATE__' }]; variants << d
    variants.each { |document| assert_raises(RuntimeError) { M.patch_document(document, settings) } }
  end

  def test_candidate_is_not_added_to_global_or_capability_group
    after = M.patch_document(fixture, settings)
    capability = after['proxy-groups'].find { |group| group['name'] == '🧪 节点能力检测' }
    refute_includes capability['use'], M::PROVIDER
    refute after['proxy-providers'].key?(M::CANDIDATE)
    assert M.assert_no_candidate(after)
  end

  def test_conflicting_existing_managed_provider_fails_closed
    document = fixture
    document['proxy-providers'][M::PROVIDER] = { 'type' => 'file', 'path' => '/tmp/foreign.yaml' }
    error = assert_raises(RuntimeError) { M.patch_document(document, settings) }
    assert_equal 'managed_auto_provider_conflict', error.message
  end

  def test_missing_legacy_membership_fails_closed
    document = fixture
    document['proxy-groups'][0]['use'].delete('Provider_7CAD88')
    error = assert_raises(RuntimeError) { M.patch_document(document, settings) }
    assert_equal 'legacy_provider_membership_changed', error.message
  end

  def test_hook_is_inserted_before_reachable_exit_and_dead_code_stays_dead
    original = "#!/bin/sh\nrun-current\nexit 0\n# DEAD OLD HOOK\nrun-dead\n"
    patched = M.insert_hook(original)
    assert_operator patched.index(M::HOOK_BEGIN), :<, patched.index("exit 0")
    assert_operator patched.index("exit 0"), :<, patched.index('# DEAD OLD HOOK')
    assert_equal 1, patched.scan(M::HOOK_BEGIN).length
    assert_equal patched, M.insert_hook(patched)
  end

  def test_hook_refuses_ambiguous_or_missing_exit
    assert_raises(RuntimeError) { M.insert_hook("#!/bin/sh\nexit 0\nexit 0\n") }
    assert_raises(RuntimeError) { M.insert_hook("#!/bin/sh\ntrue\n") }
  end

  def test_empty_placeholder_contract_and_mixed_payload_rejection
    good = YAML.dump('proxies' => [{ 'name' => M::EMPTY_AUTO, 'type' => 'socks5', 'server' => '127.0.0.1', 'port' => 9, 'udp' => false }])
    assert_equal M::EMPTY_AUTO, M.validate_provider_payload(good)['proxies'][0]['name']
    mixed = YAML.dump('proxies' => [
      { 'name' => M::EMPTY_AUTO, 'type' => 'socks5', 'server' => '127.0.0.1', 'port' => 9, 'udp' => false },
      { 'name' => 'real', 'type' => 'ss', 'server' => '203.0.113.1', 'port' => 443 }
    ])
    assert_raises(RuntimeError) { M.validate_provider_payload(mixed) }
  end

  def test_network_provider_yaml_rejects_objects_and_aliases
    object_tag = "--- !ruby/object:Object {}\n"
    aliases = "---\nproxies: &nodes\n- name: node\n  type: socks5\n  server: 127.0.0.1\n  port: 9\ncopy: *nodes\n"
    assert_raises(StandardError) { M.validate_provider_payload(object_tag) }
    assert_raises(StandardError) { M.validate_provider_payload(aliases) }
  end

  def test_manual_rollback_blocks_a_direct_managed_node_selection
    choices = { '🛟 稳定自动' => 'admitted-us-1', '💬 对话助手' => '🛟 稳定自动' }
    assert_equal ['🛟 稳定自动', 'admitted-us-1'], M.rollback_blocker(choices, ['admitted-us-1'])
    assert_nil M.rollback_blocker({ '💬 对话助手' => '🛟 稳定自动' }, ['admitted-us-1'])
  end

  def test_endpoint_rejects_wrong_port_host_or_short_token
    bad_port = settings.merge('server_port' => 3104)
    bad_host = settings.merge('server_host' => 'server.local')
    bad_token = settings.merge('publish_token' => 'short')
    [bad_port, bad_host, bad_token].each { |value| assert_raises(RuntimeError) { M.endpoint_url(value) } }
  end

  def test_native_validation_copy_contains_no_publish_token
    staged = M.validation_document(fixture, settings, '/private/managed-auto.yaml')
    serialized = YAML.dump(staged)
    refute_includes serialized, 'a' * 64
    assert_equal 'http://127.0.0.1:9/redacted-managed-auto.yaml', staged['proxy-providers'][M::PROVIDER]['url']
    assert_equal '/private/managed-auto.yaml', staged['proxy-providers'][M::PROVIDER]['path']
  end

  def transaction(phase = 'applying')
    { 'phase' => phase, 'backup' => '/private/backup', 'settings' => {}, 'source' => '/private/source.yaml',
      'runtime' => '/private/runtime.yaml', 'owned_sha256' => {},
      'files' => { '/private/source.yaml' => { 'missing' => true }, '/private/runtime.yaml' => { 'missing' => true } },
      'rules_before' => ['MATCH,DIRECT'], 'core_pid_before' => '123' }
  end

  def test_prepared_abort_needs_no_api_or_guard_file
    writes = []
    tx = transaction('prepared')
    with_stubs(atomic: ->(*args) { writes << args }, api: ->(*) { flunk 'prepared abort must not call API' }) do
      assert M.rollback_internal(tx, false, false)
    end
    assert_equal '/private/backup/transaction.cancelled.private.yaml', writes.first[0]
  end

  def test_automatic_api_failure_restores_disk_then_leaves_inventory_pending_for_guard_retry
    tx = transaction
    restored = []
    writes = []
    with_stubs(api: ->(*) { raise 'api_down' }, restore_file: ->(_transaction, path) { restored << path },
      atomic: ->(*args) { writes << args }) do
      error = assert_raises(RuntimeError) { M.rollback_internal(tx, true, true) }
      assert_equal 'managed_inventory_unavailable', error.message
    end
    assert_equal 'rollback_inventory_pending', tx['phase']
    assert_equal ['/private/source.yaml', '/private/runtime.yaml'], restored
    assert writes.any? { |args| args[0] == M::TRANSACTION }
  end

  def test_manual_inventory_failure_is_fail_closed_before_disk_restore
    tx = transaction
    restored = []
    with_stubs(api: ->(*) { raise 'api_down' }, restore_file: ->(_transaction, path) { restored << path }) do
      error = assert_raises(RuntimeError) { M.rollback_internal(tx, false, false) }
      assert_equal 'api_down', error.message
    end
    assert_empty restored
  end

  def test_known_direct_managed_selection_blocks_guard_and_manual_rollback
    tx = transaction
    restored = []
    api_stub = lambda do |path, *_args|
      if path == '/proxies'
        { 'proxies' => { '🧭 手动选择' => { 'type' => 'Selector', 'now' => 'admitted-us-1' } } }
      else
        { 'providers' => { M::PROVIDER => { 'proxies' => [{ 'name' => 'admitted-us-1' }] } } }
      end
    end
    [false, true].each do |automatic|
      with_stubs(api: api_stub, restore_file: ->(_transaction, path) { restored << path }) do
        error = assert_raises(RuntimeError) { M.rollback_internal(tx, automatic, automatic) }
        assert_equal 'managed_node_selected_rollback_refused', error.message
      end
    end
    assert_empty restored
  end

  def test_pending_rollback_can_finish_after_api_recovers
    tx = transaction('rollback_api_pending')
    tx['owned_sha256'] = { '/private/source.yaml' => 'owned', '/private/runtime.yaml' => 'owned' }
    restored = []
    document = { 'proxy-providers' => {}, 'proxy-groups' => [], 'rules' => ['MATCH,DIRECT'] }
    api_stub = lambda do |path, *_args|
      case path
      when '/proxies' then { 'proxies' => {} }
      when '/providers/proxies' then { 'providers' => {} }
      when '/rules' then { 'rules' => ['MATCH,DIRECT'] }
      else {}
      end
    end
    with_stubs(api: api_stub, restore_file: ->(_transaction, path) { restored << path },
      load_hash: ->(_path) { document }, load_backup_document: ->(_transaction, _path) { document },
      core_pid: '123', atomic: ->(*) {}) do
      assert M.rollback_internal(tx, false, false)
    end
    assert_equal ['/private/source.yaml', '/private/runtime.yaml'], restored
  end

  def test_accept_cas_helper_rejects_foreign_owned_file_change
    Dir.mktmpdir('managed-router-cas') do |dir|
      path = File.join(dir, 'owned.yaml')
      File.write(path, 'foreign')
      tx = { 'owned_sha256' => { path => 'owned-digest' }, 'files' => { path => { 'sha256' => 'before-digest' } } }
      with_stubs(hash_file: 'foreign-digest') do
        error = assert_raises(RuntimeError) { M.check_owned_baseline(tx, [path]) }
        assert_equal 'router_concurrent_edit_refused', error.message
      end
    end
  end
end
