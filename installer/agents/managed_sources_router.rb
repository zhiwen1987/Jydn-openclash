require 'yaml'

# Stand-alone, reversible OpenClash transaction agent. Candidate nodes remain
# in admission_queue.py's isolated Mihomo process; production only sees nodes
# already admitted into Managed_Auto.
module ManagedSourcesRouter
  BASE = '/etc/openclash/custom/jydn-managed-sources'.freeze
  AGENT = (BASE + '/agent.rb').freeze
  SETTINGS = (BASE + '/settings.yaml').freeze
  TRANSACTION = (BASE + '/transaction.yaml').freeze
  STATE = (BASE + '/state.yaml').freeze
  LOCK = (BASE + '/operations.lock').freeze
  GUARD_INIT = '/etc/init.d/jydn-managed-sources-guard'.freeze
  OVERWRITE = '/etc/openclash/custom/openclash_custom_overwrite.sh'.freeze
  CORE = '/etc/openclash/core/clash_meta'.freeze
  PROVIDER = 'Managed_Auto'.freeze
  CANDIDATE = 'Managed_Candidate'.freeze
  EMPTY_AUTO = '__STACK_EMPTY_MANAGED_AUTO__'.freeze
  ROUTING_OWNER = 'managed-sources-router/v1'.freeze
  HOOK_BEGIN = '# BEGIN JYDN MANAGED AUTO'.freeze
  HOOK_END = '# END JYDN MANAGED AUTO'.freeze
  TECHNICAL_GROUPS = ['GLOBAL', '🧪 节点能力检测', '🔬 节点归属校验'].freeze
  AUTO_GROUPS = [
    '🛟 稳定自动', '♻️ 自动选择', '🇭🇰 香港', '🇹🇼 台湾', '🇯🇵 日本',
    '🇸🇬 新加坡', '🇰🇷 韩国', '🇬🇧 英国', '🇩🇪 德国', '🇺🇸 美国', '🌍 其他地区'
  ].freeze
  MANUAL_GROUPS = ['🧭 手动选择', '🔐 自定义节点'].freeze
  CONSUMER_GROUPS = (AUTO_GROUPS + MANUAL_GROUPS).freeze
  LEGACY_PUBLIC_PROVIDERS = ['Provider_BFFC55', 'Provider_7CAD88'].freeze

  module_function

  def assert(value, message); raise message unless value; end

  def json(value)
    case value
    when Hash then '{' + value.map { |k, v| json(k.to_s) + ':' + json(v) }.join(',') + '}'
    when Array then '[' + value.map { |v| json(v) }.join(',') + ']'
    when String
      '"' + value.each_char.map { |c| c == '"' ? '\\"' : c == "\\" ? '\\\\' : c.ord < 32 ? ('\\u%04x' % c.ord) : c }.join + '"'
    when Integer, Float then value.to_s
    when TrueClass then 'true'
    when FalseClass then 'false'
    when NilClass then 'null'
    else raise 'json_type_invalid'
    end
  end

  def deep_copy(value); Marshal.load(Marshal.dump(value)); end

  def sh(*args)
    output = IO.popen(args, err: File::NULL) { |stream| stream.read }
    raise 'command_failed' unless $?.success?
    output.strip
  end

  def bounded(args, seconds, out: File::NULL, err: File::NULL)
    pid = Process.spawn(*args, pgroup: true, out: out, err: err)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      result = Process.waitpid2(pid, Process::WNOHANG)
      return result[1].success? if result
      if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        begin Process.kill('TERM', -pid); rescue Errno::ESRCH; end
        sleep 1
        begin Process.kill('KILL', -pid); rescue Errno::ESRCH; end
        begin Process.waitpid(pid); rescue Errno::ECHILD; end
        return false
      end
      sleep 0.2
    end
  end

  def atomic(path, raw, mode = 0600)
    sh('mkdir', '-p', '-m', '700', File.dirname(path))
    temporary = path + '.managed-' + Process.pid.to_s
    File.open(temporary, 'wb', mode) { |file| file.write(raw); file.flush; file.fsync }
    File.chmod(mode, temporary)
    File.rename(temporary, path)
  end

  def hash_file(path); sh('sha256sum', path).split.first; end

  def load_hash(path)
    value = YAML.load_file(path)
    assert(value.is_a?(Hash), 'yaml_root_invalid')
    value
  end

  def with_lock(blocking = false)
    sh('mkdir', '-p', '-m', '700', BASE)
    File.open(LOCK, 'a', 0600) do |file|
      flags = File::LOCK_EX
      flags |= File::LOCK_NB unless blocking
      assert(file.flock(flags), 'router_operation_in_progress')
      begin yield ensure file.flock(File::LOCK_UN) end
    end
  end

  def uci(key)
    IO.popen(['uci', '-q', 'get', 'openclash.config.' + key], err: File::NULL) { |stream| stream.read }.strip
  end

  def active?; system('pidof', 'clash_meta', out: File::NULL, err: File::NULL); end
  def core_pid; sh('pidof', 'clash_meta').split.first; rescue StandardError; nil; end

  def api(path, method = 'GET', body = nil, settings = nil)
    port = settings ? settings['api_port'].to_i : uci('cn_port').to_i
    port = 9090 if port == 0
    secret = settings ? settings['api_secret'].to_s : uci('dashboard_password')
    config = 'url = ' + json('http://127.0.0.1:' + port.to_s + path) + "\n"
    config += 'header = ' + json('Authorization: Bearer ' + secret) + "\nrequest = " + json(method) + "\n"
    config += 'header = "Content-Type: application/json"' + "\ndata-binary = " + json(json(body)) + "\n" if body
    output = IO.popen(['curl', '-fsS', '--max-time', '30', '--config', '-'], 'r+', err: File::NULL) do |stream|
      stream.write(config); stream.close_write; stream.read
    end
    raise 'api_request_failed' unless $?.success?
    output.strip.empty? ? {} : YAML.load(output)
  end

  def percent_encode(value)
    value.to_s.bytes.map { |b| b.chr.match?(/[A-Za-z0-9_.~-]/) ? b.chr : ('%%%02X' % b) }.join
  end

  def assert_writer_hold(request)
    assert(request['routing_owner'] == ROUTING_OWNER, 'routing_owner_invalid')
    assert(request['server_writer_hold'] == true, 'server_writer_hold_required')
  end

  def assert_router_identity(request)
    expected = request['router_mac'].to_s.downcase
    assert(expected.match?(/\A(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\z/), 'router_mac_invalid')
    actual = File.read('/sys/class/net/br-lan/address').strip.downcase
    assert(actual == expected, 'router_identity_changed')
  end

  def assert_no_candidate(value)
    case value
    when Hash
      value.each { |key, item| assert(!key.to_s.include?(CANDIDATE), 'candidate_provider_forbidden'); assert_no_candidate(item) }
    when Array then value.each { |item| assert_no_candidate(item) }
    when String
      assert(!value.include?(CANDIDATE), 'candidate_provider_forbidden')
      assert(!value.include?('__STACK_EMPTY_MANAGED_CANDIDATE__'), 'candidate_provider_forbidden')
    end
    true
  end

  def endpoint_url(settings)
    host = settings['server_host'].to_s
    port = settings['server_port'].to_i
    token = settings['publish_token'].to_s
    assert(host.match?(/\A(?:\d{1,3}\.){3}\d{1,3}\z/), 'server_host_invalid')
    assert(host.split('.').all? { |p| p.to_i.between?(0, 255) && p == p.to_i.to_s }, 'server_host_invalid')
    assert(port == 3103, 'server_port_invalid')
    assert(token.match?(/\A[0-9a-fA-F]{64}\z/), 'publish_token_invalid')
    'http://' + host + ':' + port.to_s + '/providers/' + PROVIDER + '.yaml?token=' + token
  end

  def provider_definition(settings)
    { 'type' => 'http', 'url' => endpoint_url(settings), 'path' => './proxy_provider/' + PROVIDER + '.yaml',
      'interval' => 3600, 'health-check' => { 'enable' => false } }
  end

  def patch_document(document, settings)
    assert(document.is_a?(Hash), 'config_root_invalid')
    assert_no_candidate(document)
    result = deep_copy(document)
    providers = result['proxy-providers']
    assert(providers.is_a?(Hash), 'proxy_providers_missing')
    expected = provider_definition(settings)
    providers.key?(PROVIDER) ? assert(providers[PROVIDER] == expected, 'managed_auto_provider_conflict') : providers[PROVIDER] = expected
    groups = result['proxy-groups']
    assert(groups.is_a?(Array), 'proxy_groups_missing')
    names = groups.map { |group| group['name'] }
    assert(names.uniq.length == names.length, 'proxy_group_name_duplicate')
    assert((CONSUMER_GROUPS - names).empty?, 'managed_auto_target_group_missing')
    groups.each do |group|
      next unless CONSUMER_GROUPS.include?(group['name'])
      use = group['use']
      assert(use.is_a?(Array), 'managed_auto_target_use_missing')
      assert((LEGACY_PUBLIC_PROVIDERS - use).empty?, 'legacy_provider_membership_changed')
      use << PROVIDER unless use.include?(PROVIDER)
    end
    assert_managed_membership(result)
    result
  end

  def assert_managed_membership(document)
    assert_no_candidate(document)
    actual = document.fetch('proxy-groups').select { |g| Array(g['use']).include?(PROVIDER) }.map { |g| g['name'] }
    assert(actual.sort == CONSUMER_GROUPS.sort, 'managed_auto_membership_invalid')
    true
  end

  def strip_managed_auto(document)
    result = deep_copy(document)
    result.fetch('proxy-providers', {}).delete(PROVIDER)
    Array(result['proxy-groups']).each { |group| group['use'].delete(PROVIDER) if group['use'].is_a?(Array) }
    result
  end

  def hook_block
    HOOK_BEGIN + "\n" +
      'if ! ruby -E UTF-8 ' + AGENT + ' hook ' + SETTINGS + ' "$CONFIG_FILE"; then' + "\n" +
      '  printf \'%s [warning] Managed_Auto override failed; previous configuration retained\\n\' "$(date \'+%Y-%m-%d %H:%M:%S\')" >> /tmp/openclash.log' + "\n" +
      "  exit 1\nfi\n" + HOOK_END + "\n"
  end

  def insert_hook(original)
    assert(original.is_a?(String), 'overwrite_invalid')
    cleaned = original.gsub(/#{Regexp.escape(HOOK_BEGIN)}.*?#{Regexp.escape(HOOK_END)}\n?/m, '')
    assert(cleaned.scan(/^\s*exit\s+0\s*$/).length == 1, 'overwrite_exit_ambiguous')
    cleaned.sub(/^\s*exit\s+0\s*$/, hook_block + 'exit 0')
  end

  def hook(settings_path, config_path)
    assert(File.expand_path(settings_path) == SETTINGS, 'hook_settings_path_invalid')
    expanded = File.expand_path(config_path)
    assert(expanded.start_with?('/etc/openclash/', '/tmp/'), 'hook_config_path_invalid')
    settings = load_hash(settings_path)
    assert(settings['schema'] == 1, 'settings_schema_invalid')
    patched = patch_document(load_hash(expanded), settings)
    atomic(expanded, YAML.dump(patched), File.stat(expanded).mode & 0777)
    { 'hooked' => true, 'provider' => PROVIDER, 'automatic_group_count' => AUTO_GROUPS.length,
      'manual_selector_count' => MANUAL_GROUPS.length, 'candidate_loaded' => false }
  end

  def validate_provider_payload(raw)
    payload = YAML.safe_load(raw, permitted_classes: [], permitted_symbols: [], aliases: false)
    assert(payload.is_a?(Hash), 'provider_payload_invalid')
    assert_no_candidate(payload)
    proxies = payload['proxies']
    assert(proxies.is_a?(Array) && !proxies.empty?, 'provider_payload_empty')
    names = proxies.map { |proxy| proxy.is_a?(Hash) ? proxy['name'].to_s : '' }
    assert(names.none?(&:empty?) && names.uniq.length == names.length, 'provider_proxy_name_invalid')
    placeholders = proxies.select { |proxy| proxy['name'].to_s.start_with?('__STACK_EMPTY_MANAGED_') }
    if placeholders.any?
      assert(proxies.length == 1, 'provider_placeholder_mixed')
      assert(placeholders.first == { 'name' => EMPTY_AUTO, 'type' => 'socks5', 'server' => '127.0.0.1', 'port' => 9, 'udp' => false },
             'provider_placeholder_invalid')
    end
    payload
  end

  def fetch_provider(settings)
    config = 'url = ' + json(endpoint_url(settings)) + "\nrequest = \"GET\"\n"
    output = IO.popen(['curl', '-fsS', '--max-time', '45', '--config', '-'], 'r+', err: File::NULL) do |stream|
      stream.write(config); stream.close_write; stream.read
    end
    raise 'managed_auto_endpoint_unavailable' unless $?.success?
    validate_provider_payload(output)
    output
  end

  def snapshot_file(backup, files, path)
    assert(path.start_with?('/etc/', '/root/'), 'backup_path_invalid')
    if File.file?(path)
      name = 'file-' + files.length.to_s + '.before'
      atomic(backup + '/' + name, File.binread(path), 0600)
      files[path] = { 'file' => name, 'sha256' => hash_file(path), 'mode' => File.stat(path).mode & 0777 }
    else
      files[path] = { 'missing' => true }
    end
  end

  def managed_write(transaction, path, raw, mode = 0600)
    current = File.file?(path) ? hash_file(path) : nil
    baseline = transaction['files'].dig(path, 'sha256')
    expected = transaction['owned_sha256'][path] || baseline
    assert(current == expected, 'router_concurrent_edit_apply_refused')
    intent = BASE + '/intent-' + transaction['owned_sha256'].length.to_s
    atomic(intent, raw, mode)
    transaction['owned_sha256'][path] = hash_file(intent)
    atomic(TRANSACTION, json(transaction), 0600)
    atomic(path, raw, mode)
  end

  def current_paths
    source = uci('config_path')
    assert(source.start_with?('/etc/openclash/config/'), 'openclash_source_path_invalid')
    assert(File.file?(source), 'openclash_source_missing')
    runtime = '/etc/openclash/' + File.basename(source)
    assert(File.file?(runtime), 'openclash_runtime_missing')
    [source, runtime]
  end

  def selectors
    api('/proxies').fetch('proxies').select { |_name, group| group['type'] == 'Selector' }.transform_values { |group| group['now'] }
  end

  def api_rules; api('/rules').fetch('rules'); end

  def build_settings(request)
    port = uci('cn_port').to_i
    settings = { 'schema' => 1, 'server_host' => request['server_host'], 'server_port' => request['server_port'] || 3103,
      'publish_token' => request['publish_token'], 'api_port' => port == 0 ? 9090 : port,
      'api_secret' => uci('dashboard_password'), 'routing_owner' => ROUTING_OWNER }
    endpoint_url(settings)
    settings
  end

  def preview(request)
    assert_router_identity(request)
    source, runtime = current_paths
    settings = build_settings(request)
    source_before = load_hash(source)
    runtime_before = load_hash(runtime)
    source_after = patch_document(source_before, settings)
    runtime_after = patch_document(runtime_before, settings)
    assert(strip_managed_auto(source_after) == source_before, 'source_not_minimal_delta')
    assert(strip_managed_auto(runtime_after) == runtime_before, 'runtime_not_minimal_delta')
    { 'preview' => true, 'provider' => PROVIDER, 'candidate_loaded' => false, 'automatic_groups' => AUTO_GROUPS,
      'manual_selectors' => MANUAL_GROUPS,
      'source_group_count' => source_before.fetch('proxy-groups').length,
      'runtime_group_count' => runtime_before.fetch('proxy-groups').length,
      'server_writer_hold_required' => true, 'cold_restart_required' => false }
  end

  def check_expected(request, source, runtime)
    return unless request['expected'].is_a?(Hash)
    checks = { 'source_sha256' => hash_file(source), 'runtime_sha256' => hash_file(runtime),
      'overwrite_sha256' => File.file?(OVERWRITE) ? hash_file(OVERWRITE) : nil, 'core_sha256' => hash_file(CORE) }
    checks.each { |key, value| assert(!request['expected'].key?(key) || request['expected'][key] == value, 'router_changed_before_backup') }
  end

  def prepare(request)
    assert_writer_hold(request)
    assert_router_identity(request)
    assert(!File.file?(TRANSACTION), 'unfinished_router_transaction')
    assert(!File.file?(STATE), 'accepted_transaction_requires_manual_rollback')
    assert(active?, 'openclash_not_running')
    source, runtime = current_paths
    check_expected(request, source, runtime)
    settings = build_settings(request)
    patch_document(load_hash(source), settings)
    patch_document(load_hash(runtime), settings)
    backup = '/root/clash-stack-backups/managed-sources/' + Time.now.to_i.to_s + '-' + Process.pid.to_s
    sh('mkdir', '-p', '-m', '700', backup)
    files = {}
    [source, runtime, OVERWRITE, AGENT, SETTINGS, GUARD_INIT].each { |path| snapshot_file(backup, files, path) }
    atomic(backup + '/agent.next', File.binread(__FILE__), 0600)
    seconds = Integer(request['guard_seconds'] || 600)
    assert(seconds.between?(120, 1800), 'guard_deadline_invalid')
    transaction = { 'schema' => 1, 'phase' => 'prepared', 'routing_owner' => ROUTING_OWNER,
      'server_writer_hold_contract' => true, 'backup' => backup, 'files' => files, 'owned_sha256' => {},
      'source' => source, 'runtime' => runtime, 'settings' => settings, 'choices_before' => selectors,
      'rules_before' => api_rules, 'core_pid_before' => core_pid, 'started_at' => Time.now.to_i,
      'guard_deadline' => Time.now.to_i + seconds }
    assert(!transaction['core_pid_before'].to_s.empty?, 'openclash_pid_missing')
    atomic(TRANSACTION, json(transaction), 0600)
    atomic(backup + '/transaction.prepared.private.yaml', json(transaction), 0600)
    { 'prepared' => true, 'backup' => backup, 'provider' => PROVIDER, 'candidate_loaded' => false,
      'server_writer_hold_required_until_accept' => true }
  end

  def load_backup_document(transaction, path)
    item = transaction['files'].fetch(path)
    assert(!item['missing'], 'backup_document_missing')
    load_hash(transaction['backup'] + '/' + item['file'])
  end

  def check_owned_baseline(transaction, paths)
    paths.each do |path|
      current = File.file?(path) ? hash_file(path) : nil
      item = transaction['files'].fetch(path)
      assert(current == (transaction['owned_sha256'][path] || item['sha256']), 'router_concurrent_edit_refused')
    end
  end

  def validation_document(runtime_document, settings, provider_path)
    staged = patch_document(runtime_document, settings)
    staged_provider = staged.fetch('proxy-providers').fetch(PROVIDER)
    staged_provider['path'] = provider_path
    # Native validation must never persist or print the private publish token.
    staged_provider['url'] = 'http://127.0.0.1:9/redacted-managed-auto.yaml'
    staged
  end

  def native_validate(runtime_document, settings, provider_raw)
    stage_dir = BASE + '/validation'
    sh('mkdir', '-p', '-m', '700', stage_dir)
    provider_path = stage_dir + '/managed-auto.yaml'
    atomic(provider_path, provider_raw, 0600)
    staged = validation_document(runtime_document, settings, provider_path)
    config_path = stage_dir + '/candidate.yaml'
    atomic(config_path, YAML.dump(staged), 0600)
    assert(bounded([CORE, '-t', '-d', '/etc/openclash', '-f', config_path], 180), 'native_router_validation_failed')
  end

  def guard_init
    "#!/bin/sh /etc/rc.common\nSTART=99\nUSE_PROCD=1\n" +
      "start_service() {\n  procd_open_instance\n" +
      "  procd_set_param command /usr/bin/ruby -E UTF-8 #{AGENT} guard\n" +
      "  procd_set_param stderr 1\n  procd_close_instance\n}\n"
  end

  def service(action); assert(bounded([GUARD_INIT, action], 60), 'guard_service_action_failed'); end

  def apply(request)
    assert_writer_hold(request)
    assert_router_identity(request)
    transaction = load_hash(TRANSACTION)
    assert(transaction['phase'] == 'prepared', 'router_phase_invalid')
    assert(transaction['guard_deadline'].to_i > Time.now.to_i + 60, 'guard_deadline_too_close')
    source = transaction['source']; runtime = transaction['runtime']
    check_owned_baseline(transaction, [source, runtime, OVERWRITE, AGENT, SETTINGS, GUARD_INIT])
    settings = transaction['settings']
    provider_raw = fetch_provider(settings)
    source_before = load_hash(source); runtime_before = load_hash(runtime)
    assert(source_before == load_backup_document(transaction, source), 'source_changed_after_backup')
    assert(runtime_before == load_backup_document(transaction, runtime), 'runtime_changed_after_backup')
    source_after = patch_document(source_before, settings)
    runtime_after = patch_document(runtime_before, settings)
    overwrite_before = File.file?(OVERWRITE) ? File.read(OVERWRITE) : "#!/bin/sh\nexit 0\n"
    overwrite_after = insert_hook(overwrite_before)
    native_validate(runtime_before, settings, provider_raw)
    transaction['phase'] = 'applying'
    atomic(TRANSACTION, json(transaction), 0600)
    begin
      managed_write(transaction, AGENT, File.binread(transaction['backup'] + '/agent.next'), 0700)
      managed_write(transaction, SETTINGS, YAML.dump(settings), 0600)
      managed_write(transaction, GUARD_INIT, guard_init, 0755)
      service('enable'); service('start')
      managed_write(transaction, source, YAML.dump(source_after), transaction['files'][source]['mode'])
      managed_write(transaction, runtime, YAML.dump(runtime_after), transaction['files'][runtime]['mode'])
      managed_write(transaction, OVERWRITE, overwrite_after, transaction['files'][OVERWRITE]['mode'] || 0755)
      api('/configs?force=true', 'PUT', { 'path' => runtime }, settings)
      transaction['phase'] = 'applied'
      atomic(TRANSACTION, json(transaction), 0600)
      verify_transaction(transaction)
    rescue StandardError
      begin rollback_internal(transaction, true, false) rescue StandardError; raise 'apply_failed_rollback_failed' end
      raise 'apply_failed_rolled_back'
    end
    { 'applied' => true, 'provider' => PROVIDER, 'candidate_loaded' => false, 'hot_reload' => true,
      'core_pid_preserved' => true, 'guard_armed' => true }
  end

  def selector_choices_from(proxies)
    proxies.select { |_name, group| group['type'] == 'Selector' }.transform_values { |group| group['now'] }
  end

  def verify_choices(expected, proxies)
    actual = selector_choices_from(proxies)
    expected.each do |name, value|
      next if TECHNICAL_GROUPS.include?(name)
      assert(actual[name] == value, 'business_selector_choice_changed')
    end
  end

  def verify_transaction(transaction)
    assert(transaction['core_pid_before'] == core_pid, 'cold_restart_detected')
    source = load_hash(transaction['source']); runtime = load_hash(transaction['runtime'])
    source_before = load_backup_document(transaction, transaction['source'])
    runtime_before = load_backup_document(transaction, transaction['runtime'])
    assert_no_candidate(source); assert_no_candidate(runtime)
    assert_managed_membership(source); assert_managed_membership(runtime)
    assert(strip_managed_auto(source) == source_before, 'source_structure_changed')
    assert(strip_managed_auto(runtime) == runtime_before, 'runtime_structure_changed')
    overwrite_item = transaction['files'].fetch(OVERWRITE)
    overwrite_before = overwrite_item['missing'] ? "#!/bin/sh\nexit 0\n" : File.binread(transaction['backup'] + '/' + overwrite_item['file'])
    assert(File.read(OVERWRITE) == insert_hook(overwrite_before), 'overwrite_structure_changed')
    assert(api_rules == transaction['rules_before'], 'routing_rules_changed')
    verify_choices(transaction['choices_before'], api('/proxies').fetch('proxies'))
    providers = api('/providers/proxies').fetch('providers')
    assert(!providers.key?(CANDIDATE), 'candidate_provider_loaded')
    assert(providers.key?(PROVIDER), 'managed_auto_provider_not_loaded')
    nodes = Array(providers.dig(PROVIDER, 'proxies'))
    assert(!nodes.empty?, 'managed_auto_provider_empty')
    assert(nodes.none? { |node| node['name'].to_s.include?(CANDIDATE) }, 'candidate_provider_loaded')
    true
  end

  def verify(request)
    assert_writer_hold(request); assert_router_identity(request)
    transaction = load_hash(TRANSACTION)
    assert(['applied', 'verified'].include?(transaction['phase']), 'router_phase_invalid')
    check_owned_baseline(transaction, transaction['owned_sha256'].keys)
    verify_transaction(transaction)
    transaction['phase'] = 'verified'; atomic(TRANSACTION, json(transaction), 0600)
    { 'verified' => true, 'provider' => PROVIDER, 'candidate_loaded' => false,
      'automatic_group_count' => AUTO_GROUPS.length, 'manual_selector_count' => MANUAL_GROUPS.length, 'rules_preserved' => true,
      'business_choices_preserved' => true, 'cold_restart' => false }
  end

  def accept(request)
    assert_writer_hold(request); assert_router_identity(request)
    transaction = load_hash(TRANSACTION)
    assert(['applied', 'verified'].include?(transaction['phase']), 'router_phase_invalid')
    check_owned_baseline(transaction, transaction['owned_sha256'].keys)
    verify_transaction(transaction)
    transaction['phase'] = 'accepted'; transaction['accepted_at'] = Time.now.to_i
    atomic(STATE, json(transaction), 0600)
    atomic(transaction['backup'] + '/transaction.accepted.private.yaml', json(transaction), 0600)
    File.unlink(TRANSACTION)
    service('disable'); service('stop')
    { 'accepted' => true, 'provider' => PROVIDER, 'candidate_loaded' => false,
      'manual_rollback_available' => true, 'backup' => transaction['backup'] }
  end

  def managed_node_names(settings)
    providers = api('/providers/proxies', 'GET', nil, settings).fetch('providers')
    Array(providers.dig(PROVIDER, 'proxies')).map { |node| node['name'].to_s }
  end

  def rollback_blocker(choices, managed_names)
    choices.find { |name, value| !TECHNICAL_GROUPS.include?(name) && managed_names.include?(value) }
  end

  def restore_file(transaction, path)
    item = transaction['files'].fetch(path)
    current = File.file?(path) ? hash_file(path) : nil
    assert([transaction['owned_sha256'][path], item['sha256']].include?(current), 'router_concurrent_edit_restore_refused')
    return unless transaction['owned_sha256'].key?(path)
    if item['missing']
      File.unlink(path) if File.file?(path)
    else
      backup = transaction['backup'] + '/' + item['file']
      assert(hash_file(backup) == item['sha256'], 'router_backup_corrupt')
      atomic(path, File.binread(backup), item['mode'])
    end
  end

  def restore_current_choices(current_choices, settings)
    proxies = api('/proxies', 'GET', nil, settings).fetch('proxies')
    current_choices.each do |name, value|
      next if TECHNICAL_GROUPS.include?(name)
      group = proxies[name]
      next unless group && group['type'] == 'Selector' && group['now'] != value && Array(group['all']).include?(value)
      api('/proxies/' + percent_encode(name), 'PUT', { 'name' => value }, settings)
    end
  end

  def rollback_internal(transaction, automatic, from_guard)
    settings = transaction['settings']
    if transaction['phase'] == 'prepared' && transaction['owned_sha256'].empty?
      atomic(transaction['backup'] + '/transaction.cancelled.private.yaml', json(transaction), 0600)
      File.unlink(TRANSACTION) if File.file?(TRANSACTION)
      return true
    end
    current_choices = {}
    inventory_known = true
    blocker = nil
    begin
      current_choices = selector_choices_from(api('/proxies', 'GET', nil, settings).fetch('proxies'))
      blocker = rollback_blocker(current_choices, managed_node_names(settings))
    rescue StandardError
      raise unless automatic
      current_choices = {}
      inventory_known = false
    end
    assert(blocker.nil?, 'managed_node_selected_rollback_refused') if inventory_known
    ordered = transaction['owned_sha256'].keys
    preferred = [transaction['source'], transaction['runtime'], OVERWRITE]
    routing_paths = (preferred + (ordered - preferred - [AGENT, SETTINGS, GUARD_INIT])).uniq
    begin
      routing_paths.each { |path| restore_file(transaction, path) if transaction['files'].key?(path) }
    rescue StandardError
      transaction['phase'] = 'rollback_disk_pending'
      atomic(TRANSACTION, json(transaction), 0600)
      raise
    end
    unless inventory_known
      transaction['phase'] = 'rollback_inventory_pending'
      atomic(TRANSACTION, json(transaction), 0600)
      raise 'managed_inventory_unavailable'
    end
    begin
      api('/configs?force=true', 'PUT', { 'path' => transaction['runtime'] }, settings)
      restore_current_choices(current_choices, settings) unless current_choices.empty?
      assert(load_hash(transaction['runtime']) == load_backup_document(transaction, transaction['runtime']), 'runtime_restore_failed')
      assert(load_hash(transaction['source']) == load_backup_document(transaction, transaction['source']), 'source_restore_failed')
      providers = api('/providers/proxies', 'GET', nil, settings).fetch('providers')
      assert(!providers.key?(PROVIDER) && !providers.key?(CANDIDATE), 'managed_provider_restore_failed')
      assert(api_rules == transaction['rules_before'], 'routing_rules_restore_failed')
      assert(core_pid == transaction['core_pid_before'], 'cold_restart_detected')
    rescue StandardError
      transaction['phase'] = 'rollback_api_pending'
      atomic(TRANSACTION, json(transaction), 0600)
      raise
    end
    if File.file?(GUARD_INIT)
      begin service('disable') rescue StandardError end
      begin service('stop') rescue StandardError end unless from_guard
    end
    [SETTINGS, AGENT, GUARD_INIT].each { |path| restore_file(transaction, path) if transaction['files'].key?(path) }
    atomic(transaction['backup'] + '/transaction.rolled-back.private.yaml', json(transaction), 0600)
    File.unlink(TRANSACTION) if File.file?(TRANSACTION)
    File.unlink(STATE) if File.file?(STATE)
    true
  end

  def rollback(request, manual = false)
    assert_writer_hold(request); assert_router_identity(request)
    path = File.file?(TRANSACTION) ? TRANSACTION : STATE
    assert(File.file?(path), 'no_router_transaction')
    transaction = load_hash(path)
    assert(transaction['routing_owner'] == ROUTING_OWNER, 'routing_owner_invalid')
    assert(manual || transaction['phase'] != 'accepted', 'manual_rollback_required')
    rollback_internal(transaction, false, false)
    { 'rolled_back' => true, 'provider_removed' => PROVIDER, 'candidate_loaded' => false,
      'current_business_choices_preserved_when_still_valid' => true, 'cold_restart' => false,
      'backup' => transaction['backup'] }
  end

  def guard
    return { 'guard' => 'idle' } unless File.file?(TRANSACTION)
    transaction = load_hash(TRANSACTION)
    while File.file?(TRANSACTION) && Time.now.to_i < transaction['guard_deadline'].to_i
      break if transaction['phase'].to_s.start_with?('rollback_')
      sleep 5
      transaction = load_hash(TRANSACTION) if File.file?(TRANSACTION)
    end
    return { 'guard' => 'accepted' } unless File.file?(TRANSACTION)
    loop do
      begin
        result = nil
        with_lock(false) do
          if File.file?(TRANSACTION)
            rollback_internal(load_hash(TRANSACTION), true, true)
            result = 'rolled_back'
          else
            result = 'accepted'
          end
        end
        return { 'guard' => result }
      rescue StandardError => error
        status = { 'guard' => 'rollback_retry', 'error' => error.message.to_s.match?(/\A[a-z0-9_\-]+\z/) ? error.message : 'operation_failed',
          'next_retry_after_seconds' => 5 }
        atomic(BASE + '/guard-status.yaml', json(status), 0600)
        sleep 5
      end
    end
  end

  def dispatch(request)
    case request['action'].to_s
    when 'preview' then preview(request)
    when 'prepare' then prepare(request)
    when 'apply' then apply(request)
    when 'verify' then verify(request)
    when 'accept' then accept(request)
    when 'rollback' then rollback(request, false)
    when 'manual-rollback' then rollback(request, true)
    else raise 'action_invalid'
    end
  end

  def run_cli(argv)
    if argv[0] == 'hook'
      assert(argv.length == 3, 'hook_arguments_invalid')
      return hook(argv[1], argv[2])
    end
    return guard if argv[0] == 'guard'
    assert(argv.length == 1, 'request_path_required')
    with_lock { dispatch(load_hash(argv[0])) }
  end
end

unless ENV['MANAGED_SOURCES_ROUTER_LIBRARY'] == '1'
  begin
    puts ManagedSourcesRouter.json(ManagedSourcesRouter.run_cli(ARGV))
  rescue StandardError => error
    message = error.message.to_s
    message = 'operation_failed' unless message.match?(/\A[a-z0-9_\-]+\z/)
    warn ManagedSourcesRouter.json({ 'ok' => false, 'error' => message })
    exit 1
  end
end
