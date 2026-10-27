-- Pure collector. No UCI commits, shell commands, file writes or node APIs.
local M={}
function M.collect(cursor,source_name)
 local matches={}
 cursor:foreach('openclash','config_subscribe',function(s)if s.name==source_name then matches[#matches+1]=s end end)
 if #matches~=1 then return {schema=1,state='error',error='source_missing_or_ambiguous',source_name=source_name} end
 local s=matches[1];local fields=s.address
 if fields==nil then fields={} elseif type(fields)=='string' then fields={fields} end
 if type(fields)~='table' then return {schema=1,state='error',error='invalid_addresses',source_name=source_name} end
 local addresses={}
 for _,block in ipairs(fields)do
  if type(block)~='string' then return {schema=1,state='error',error='invalid_addresses',source_name=source_name} end
  for line in (block..'\n'):gmatch('([^\n]*)\n')do
   line=line:gsub('^%s+',''):gsub('%s+$','')
   if line~='' then addresses[#addresses+1]=line end
  end
 end
 if #addresses>128 then return {schema=1,state='error',error='too_many_sources',source_name=source_name} end
 return {schema=1,state='ok',source_name=source_name,enabled=s.enabled~='0',addresses=addresses,address_count=#addresses,observed_at=os.time()}
end
return M
