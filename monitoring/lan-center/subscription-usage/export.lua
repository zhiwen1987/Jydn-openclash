-- Forced-command entrypoint. No caller-controlled filename, source or command.
local json=require 'luci.jsonc'
local directory='/etc/openclash/custom/subscription-info-exporter/'
local function refuse(code)
 io.write(json.stringify({schema=1,state='error',error=code}));os.exit(1)
end
local config_file=io.open(directory..'config.json','r');if not config_file then refuse('not_configured') end
local config=json.parse(config_file:read('*a'));config_file:close()
if type(config)~='table' or config.source_name~='转换' then refuse('invalid_export_config') end
local peer=(os.getenv('SSH_CONNECTION') or ''):match('^(%S+)')
if peer~=config.client_ip then refuse('client_not_allowed') end
if os.getenv('SSH_ORIGINAL_COMMAND')~='subscription-info-export-v1' then refuse('command_not_allowed') end
local command=io.popen('uci -q changes openclash','r');local pending=command:read('*a');command:close()
if pending:match('%S') then refuse('uncommitted_uci_changes') end
local module=dofile(directory..'source_export.lua')
local result=module.collect(require('luci.model.uci').cursor(),config.source_name)
io.write(json.stringify(result))
if result.state~='ok' then os.exit(1) end
