-- Auto account metadata only. Never modifies rules, proxies or DNS.
local M = {}
local json = require 'luci.jsonc'
local uci = require('luci.model.uci').cursor()

function M.adapt(data)
    if type(data) ~= 'table' or data.schema ~= 1 or type(data.providers) ~= 'table' then
        return {auto_mode=true, providers={}, registry_state='worker_unavailable', get_time=os.time()}
    end
    local providers = {}
    for _, source in ipairs(data.providers) do
        if type(source) == 'table' and type(source.id) == 'string' and source.id:match('^[%w_.%-]+$') then
            local p = {id=source.id, name=source.name, provider_name=source.name or source.id,
                usage_status=source.usage_status, metrics=source.metrics, last_success=source.last_success,
                error=source.error, stale=source.stale, age_seconds=source.age_seconds,
                used='未获取', total='未获取', surplus='未获取', expire='null'}
            -- Compatibility fields for older dialogs: never invent zero usage.
            if type(source.metrics) == 'table' then
                local fs = require 'luci.openclash'
                local v = source.metrics
                if type(v.upload)=='number' and type(v.download)=='number' and type(v.total)=='number' then
                    local used = v.upload+v.download
                    local prefix = source.usage_status=='cached' and '[缓存] ' or ''
                    p.used=prefix..fs.filesize(used);p.total=v.total==0 and '不限量' or fs.filesize(v.total)
                    p.surplus=prefix..fs.filesize(math.max(0,v.total-used))
                    p.percent=v.total>0 and string.format('%.1f',math.max(0,(v.total-used)*100/v.total)) or nil
                    if type(v.expire)=='number' then p.expire=v.expire==0 and '长期' or os.date('%Y-%m-%d %H:%M:%S',v.expire) end
                end
            end
            providers[#providers+1]=p
        end
    end
    return {schema=1, auto_mode=true, providers=providers, source_count=#providers,
        registry_state=data.registry_state, registry_error=data.registry_error,
        get_time=os.time(), refresh_seconds=30}
end

local function request(endpoint, token)
    local nixio=require 'nixio'
    local input_read,input_write=nixio.pipe()
    local output_read,output_write=nixio.pipe()
    if not input_read or not output_read then
        for _,fd in pairs({input_read,input_write,output_read,output_write}) do if fd then fd:close() end end
        return nil
    end
    local pid=nixio.fork()
    if pid==0 then
        nixio.dup(input_read,nixio.stdin);nixio.dup(output_write,nixio.stdout)
        local null=nixio.open('/dev/null','w');if null then nixio.dup(null,nixio.stderr);null:close() end
        input_read:close();input_write:close();output_read:close();output_write:close()
        nixio.exec('/usr/bin/curl','--silent','--fail','--connect-timeout','1','--max-time','3',
            '--max-filesize','262144','--proto','=http,https','--config','-')
        os.exit(1)
    elseif not pid then
        input_read:close();input_write:close();output_read:close();output_write:close();return nil
    end
    input_read:close();output_write:close()
    input_write:writeall('url = '..json.stringify(endpoint)..'\nheader = '..json.stringify('Authorization: Bearer '..token)..'\n')
    input_write:close()
    local parts,total={},0
    while true do
        local part=output_read:read(8192)
        if not part or #part==0 then break end
        total=total+#part;if total>262144 then nixio.kill(pid,15);break end
        parts[#parts+1]=part
    end
    output_read:close();nixio.waitpid(pid)
    if total>262144 then return nil end
    local ok,value=pcall(json.parse,table.concat(parts));return ok and value or nil
end

function M.for_config(filename)
    if type(filename)~='string' then return nil end
    local base=filename:gsub('%.ya?ml$','')
    local configured=nil
    uci:foreach('openclash','subscribe_info',function(s)
        if (s.name==base or s.name==filename) and s.jydn_auto=='1' then
            configured=s;return false
        end
    end)
    if not configured then return nil end
    local endpoint=configured.url
    if type(endpoint)=='table' then endpoint=endpoint[1] end
    local token=configured.jydn_usage_token
    if type(endpoint)~='string' or not endpoint:match('^https?://[%w%.%-%[%]:]+/subscription%-info$')
        or type(token)~='string' or not token:match('^[%w_-]+$') or #token<32 or #token>128 then
        return M.adapt(nil)
    end
    return M.adapt(request(endpoint,token))
end

return M
