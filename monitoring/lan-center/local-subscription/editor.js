'use strict';
(() => {
  const el = id => document.getElementById('local-' + id);
  let csrf = '', version = 0, editing = '', busy = false;
  const labels = {queued:'待评估',unknown:'未评估',healthy:'健康',degraded:'降级',unhealthy:'不可用',stale:'结果过期',available:'可用',unavailable:'不可用'};
  const errors = {login_failed:'管理密钥不正确',login_rate_limited:'登录尝试过于频繁，请一分钟后再试',login_required:'请先解锁管理',session_or_csrf_invalid:'登录已过期，请重新解锁',version_conflict_refresh_page:'数据已更新，请刷新状态后再提交',busy_retry_later:'另一个发布任务正在进行，请稍后重试',pending_recovery_retry_later:'上次发布正在恢复，请稍后刷新',publish_failed_previous_retained:'发布失败，已保留上一版本；请刷新状态检查',native_kernel_rejected_configuration:'当前旁路由内核不接受这个配置，未发布',native_validation_unavailable:'内核校验暂不可用，未发布'};
  function message(text, error=false) { const box=el('result'); box.textContent=text;box.setAttribute('role',error?'alert':'status');if(error)box.focus(); }
  async function api(path, data) {
    const r=await fetch('/api/local/'+path,{method:data?'POST':'GET',cache:'no-store',credentials:'same-origin',headers:data?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:data?JSON.stringify(data):undefined});
    const value=await r.json();if(!r.ok)throw new Error(errors[value.error]||('操作未完成：'+value.error));return value;
  }
  function locked(value) {el('login').hidden=!value;el('controls').hidden=value;}
  function stopEdit(){editing='';el('mode').disabled=false;el('cancel').hidden=true;el('links').value='';}
  async function load(){
    const s=await api('status');csrf=s.csrf;version=s.version;locked(false);
    el('summary').textContent='已保存 '+s.count+' 个自建节点 · 版本 '+version+'\n旁路由：'+(s.router_loaded?'已读取并核验':'等待读取／核验')+(s.pending_recovery?' · 正在恢复上一版本':'')+'\n健康检测独立排队；“已加载”不代表业务可用。';
    const body=el('nodes');body.replaceChildren();
    if(!s.nodes.length){const tr=body.insertRow();const td=tr.insertCell();td.colSpan=4;td.textContent='尚未添加自建节点。现有机场节点和业务选择保持原状。';}
    for(const n of s.nodes){
      const tr=body.insertRow();tr.insertCell().textContent=n.label;tr.insertCell().textContent=n.type;
      tr.insertCell().textContent=(labels[n.health]||n.health)+(n.evaluated_at?' · '+new Date(n.evaluated_at*1000).toLocaleString():'');
      const actions=tr.insertCell();const edit=document.createElement('button');edit.textContent='编辑';edit.type='button';edit.addEventListener('click',()=>{editing=n.id;el('mode').disabled=true;el('cancel').hidden=false;el('links').value='';el('links').focus();message('正在编辑：'+n.label+'。请粘贴一条新的完整链接，再保存发布。');});actions.append(edit);
      const remove=document.createElement('button');remove.textContent='删除';remove.type='button';remove.addEventListener('click',()=>run(async()=>{if(!confirm('删除「'+n.label+'」？若它正在使用，自定义节点入口会先阻断。'))return;await api('publish',{mode:'remove',ids:[n.id],version});await load();message('节点已删除，旁路由已核验。');}));actions.append(remove);
    }
  }
  async function run(fn){if(busy)return;busy=true;el('editor')?.setAttribute('aria-busy','true');document.querySelectorAll('#local-editor button').forEach(b=>b.disabled=true);try{await fn();}catch(e){message(e.message,true);}finally{busy=false;el('editor')?.removeAttribute('aria-busy');document.querySelectorAll('#local-editor button').forEach(b=>b.disabled=false);}}
  el('login').addEventListener('submit',e=>{e.preventDefault();run(async()=>{const v=await api('login',{token:el('token').value});el('token').value='';csrf=v.csrf;await load();message('管理已解锁。');});});
  el('preview').addEventListener('click',()=>run(async()=>{message('正在本地解析并用旁路由同版内核校验…');const p=await api('preview',{text:el('links').value});message('解析及内核校验通过：'+p.count+' 个去重节点。尚未保存或发布。\n'+p.nodes.map(n=>n.label+'（'+n.type+'）').join('\n'));}));
  el('form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{if(!editing&&el('mode').value==='replace'&&!confirm('替换全部自建节点？正在使用且被移除的节点将先阻断。'))return;message('正在校验、保存并发布，等待旁路由读取确认…');const r=await api('publish',{mode:editing?'edit':el('mode').value,id:editing,version,text:el('links').value});stopEdit();await load();message(r.status==='unchanged'?'内容未变，无需重复发布。':'已发布并核验节点入口；健康检测自动排队，暂未评估的节点不会被标成可用。');});});
  el('cancel').addEventListener('click',stopEdit);el('refresh').addEventListener('click',()=>run(load));
  el('logout').addEventListener('click',()=>run(async()=>{await api('logout',{});csrf='';stopEdit();locked(true);el('nodes').replaceChildren();message('管理已退出。');}));
  api('status').then(load).catch(()=>locked(true));setInterval(()=>{if(csrf&&!busy)load().catch(()=>{csrf='';locked(true);message('会话过期，请重新解锁。');});},15000);
})();
