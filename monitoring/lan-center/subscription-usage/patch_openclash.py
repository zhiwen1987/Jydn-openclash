"""Narrow, fail-closed hooks into the inspected OpenClash metadata UI only."""
from pathlib import Path


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('openclash_usage_anchor_changed')
    return text.replace(before, after, 1)


def controller(text):
    marker = '-- JYDN AUTO SUBSCRIPTION USAGE'
    if marker in text:
        raise ValueError('already_patched_requires_owned_baseline')
    before = 'function sub_info_get()\n'
    after = before + '''\t-- JYDN AUTO SUBSCRIPTION USAGE
\tlocal usage_ok, usage_module = pcall(require, 'luci.jydn_subscription_usage')
\tif usage_ok then
\t\tlocal usage = usage_module.for_config(HTTP.formvalue('filename'))
\t\tif usage then HTTP.prepare_content('application/json'); HTTP.write_json(usage); return end
\tend
'''
    return replace_once(text, before, after)


def status(text, ui):
    text = replace_once(text, 'r.providers.length>0?this.currentConfigFile===e&&this.displaySubscriptionInfo(r)',
                        '(r.providers.length>0||r.auto_mode)?this.currentConfigFile===e&&this.displaySubscriptionInfo(r)')
    text = replace_once(text, 's=1800;', 's=r.auto_mode?15:1800;')
    text = replace_once(text, 'g!==p&&p>g&&(u=!0)', 'g!==p&&p>g&&!d.auto_mode&&(u=!0)')
    text = replace_once(text, 'c&&c.status==200&&d.providers.length>0',
                        'c&&c.status==200&&(d.providers.length>0||d.auto_mode)')
    text = replace_once(text, 'SubscriptionManager.startAutoUpdate()},6e4*15)',
                        'SubscriptionManager.startAutoUpdate()},3e4)')
    text = text.replace('"sub_info_"', '"sub_info_auto_v1_"')
    return text+'\n/* JYDN AUTO SUBSCRIPTION USAGE */\n'+ui


def upload(text, ui):
    before = 'r.innerHTML="";for(var i=n&&n.status==200&&s&&s.providers?s.providers:[]'
    after = ('r.innerHTML="";if(s&&s.auto_mode&&window.JydnUsageUI){window.JydnUsageUI.render(r,s);'
             'var usageBox=t.el("sub-info-box");if(usageBox)usageBox.classList.remove("oc-hidden");return;}'
             'for(var i=n&&n.status==200&&s&&s.providers?s.providers:[]')
    return replace_once(text, before, after)+'\n/* JYDN AUTO SUBSCRIPTION USAGE */\n'+ui


def widget(text):
    text = replace_once(text, '<script type="text/javascript">',
        '<script src="/luci-static/resources/openclash/js/jydn_subscription_usage.js?v=1"></script>\n<script type="text/javascript">')
    text = replace_once(text, 'function display_progressbar(id, status) {',
        'function display_progressbar(id, status) {\n    if(status && status.auto_mode && window.JydnUsageUI){ window.JydnUsageUI.render(document.getElementById(id),status); return; }')
    text = replace_once(text, 'var halfHourInSeconds = 30 * 60;',
                        'var halfHourInSeconds = save_info.auto_mode ? 15 : 30 * 60;')
    text = replace_once(text, '(x && x.status == 200 && status.providers.length > 0)',
                        '(x && x.status == 200 && (status.providers.length > 0 || status.auto_mode))')
    text = replace_once(text, 'save_info_length !== newProvidersLength && save_info_length > newProvidersLength',
                        '!status.auto_mode && save_info_length !== newProvidersLength && save_info_length > newProvidersLength')
    text = text.replace('sub_info_<%=filename%>', 'sub_info_auto_v1_<%=filename%>')
    return text.replace('60000*15', '30000')


def stage(captured, output):
    captured, output = Path(captured), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    ui=(Path(__file__).parents[1]/'local-subscription/usage_ui.js').read_text(encoding='utf-8')
    for name, patch in [('controller.lua', controller), ('status.js', lambda t: status(t,ui)),
                        ('config_upload.js', lambda t: upload(t,ui)), ('sub_info_show.htm', widget)]:
        with (output/name).open('w',encoding='utf-8',newline='\n') as stream:
            stream.write(patch((captured/name).read_text(encoding='utf-8')))


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('captured');p.add_argument('output');args=p.parse_args();stage(args.captured,args.output)
