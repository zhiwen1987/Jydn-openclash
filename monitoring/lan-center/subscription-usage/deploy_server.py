"""Scoped live metadata overlay; keeps the container, DNS and Kuma running.

Run as root on the Docker host with a private receipt directory. A bundle maps
absolute files to base64 content; only the accepted fixed wrapper and metadata
directory are allowed. Existing release manifest is preserved as audit evidence.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

STATE = Path('/opt/clash-stack/production/state.json')
WRAPPER = Path('/opt/clash-stack/production/releases/0.1.1/payload/center/subscription-controller.py')
CONTROL = Path('/root/dpanel/compose/lan-center/data/failover')
CODE = CONTROL/'subscription-usage/code'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).is_file() else None


def atomic(path, raw, mode=0o600, inplace=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if inplace:
        # Docker file bind mounts retain the original inode.
        with path.open('r+b') as stream:
            stream.seek(0); stream.write(raw); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
        os.chmod(path, mode)
    else:
        temporary = path.with_name(path.name+'.usage-'+str(os.getpid()))
        with temporary.open('wb') as stream:
            os.chmod(temporary, mode); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)


def write(path, value):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2).encode())


def docker(*args):
    return subprocess.check_output(['docker', *args], stderr=subprocess.DEVNULL, timeout=20)


def identity():
    x = json.loads(docker('inspect', 'clash-center'))[0]
    return {'id': x['Id'], 'image': x['Image'], 'started_at': x['State']['StartedAt']}


def restart_subscription():
    code = """import os,signal
from pathlib import Path
p=int(Path('/data/subscription-controller.pid').read_text())
assert Path('/proc/'+str(p)+'/cmdline').read_bytes().split(b'\\0')[:2]==[b'/usr/bin/python3',b'/subscription-controller.py']
os.kill(p,signal.SIGTERM)
"""
    docker('exec', 'clash-center', 'python3', '-B', '-c', code)


def check(journal):
    if identity() != journal['container']:
        raise ValueError('container_identity_changed')
    for name, item in journal['files'].items():
        if item['before'] is not None and sha(item['backup']) != item['before']:
            raise ValueError('backup_corrupt')
        if sha(name) not in (item['before'], item['after']):
            raise ValueError('later_edit_requires_review')


def rollback(receipt):
    j = json.loads((receipt/'usage-journal.json').read_text())
    check(j)
    changed = False
    for name, item in j['files'].items():
        if sha(name) == item['before']:
            continue
        changed = True
        if item['before'] is None:
            Path(name).unlink(missing_ok=True)
        else:
            atomic(name, Path(item['backup']).read_bytes(), item['mode'], Path(name) == WRAPPER)
    (CONTROL/'subscription-controller/usage-reload-defer.json').unlink(missing_ok=True)
    if changed:
        restart_subscription()
    write(receipt/'USAGE_ROLLED_BACK.json', {'at': time.time(), 'subscription_reloaded': changed})
    return {'restored': True, 'subscription_reloaded': changed}


def prepare(receipt, bundle):
    assert not (receipt/'usage-journal.json').exists(), 'receipt_already_prepared'
    current = identity()
    state = json.loads(STATE.read_text())
    assert state['container_id'] == current['id'], 'managed_container_changed'
    key = 'payload/center/subscription-controller.py'
    assert sha(WRAPPER) == state['manifest']['payload_files'][key], 'preexisting_wrapper_drift'
    files = {}
    for name, encoded in bundle.items():
        path = Path(name)
        assert path == WRAPPER or path.parent == CODE and path.name in ('subscription_usage.py', 'usage_ui.js', 'usage.html'), 'target_not_allowed'
        raw = base64.b64decode(encoded, validate=True)
        target = receipt/('usage-before-'+str(len(files)))
        before = sha(path)
        mode = path.stat().st_mode & 0o777 if before else 0o600
        if before:
            atomic(target, path.read_bytes())
        stage = receipt/('usage-stage-'+str(len(files)))
        atomic(stage, raw)
        files[str(path)] = {'before': before, 'after': sha(stage), 'mode': mode, 'backup': str(target), 'stage': str(stage)}
    assert str(WRAPPER) in files, 'wrapper_required'
    state_before = receipt/'usage-state.before.json'
    atomic(state_before, STATE.read_bytes())
    # Keep original manifest and every before/after hash, rather than claiming
    # that the released offline archive contains this incremental overlay.
    state.setdefault('runtime_overlay_history', []).append({'feature': 'subscription-usage-auto-v1', 'receipt': str(receipt),
        'epoch': time.time(), 'original_payload_files': {key: state['manifest']['payload_files'][key]},
        'files': {name: {'before': v['before'], 'after': v['after']} for name, v in files.items()}})
    state['manifest']['payload_files'][key] = files[str(WRAPPER)]['after']
    stage = receipt/'usage-state.stage.json'; write(stage, state)
    files[str(STATE)] = {'before': sha(STATE), 'after': sha(stage), 'mode': 0o600, 'backup': str(state_before), 'stage': str(stage)}
    journal = {'schema': 1, 'container': current, 'files': files, 'prepared_at': time.time()}
    write(receipt/'usage-journal.json', journal); check(journal)
    return {'prepared': True, 'files': len(files), 'rollback_precheck': True}


def apply(receipt):
    j = json.loads((receipt/'usage-journal.json').read_text()); check(j)
    assert not (receipt/'USAGE_ACCEPTED.json').exists(), 'already_accepted'
    assert all(sha(name) == v['before'] for name,v in j['files'].items()), 'apply_requires_original_baseline'
    for v in j['files'].values():
        assert sha(v['stage']) == v['after'], 'staged_file_changed'
    # Independent host process performs scoped rollback after 20 minutes.
    log = (receipt/'usage-guard.log').open('ab')
    subprocess.Popen([sys.executable, str(receipt/'deploy_server.py'), 'guard', str(receipt)],
        stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, close_fds=True)
    log.close()
    try:
        health_path = CONTROL/'subscription-controller/health.json'
        health = json.loads(health_path.read_text())
        manifest = json.loads((CONTROL/'subscription-controller/current.json').read_text())
        # A bounded metadata acceptance window prevents a forced node-fetch
        # cycle on this web-worker reload. Ordinary scheduling resumes afterward.
        defer = CONTROL/'subscription-controller/usage-reload-defer.json'
        assert not defer.exists(), 'existing_reload_defer_requires_review'
        write(defer, {'until': time.time()+300, 'release_id': manifest['release_id'], 'health': health,
                      'information_only_acceptance': True})
        for name,v in j['files'].items():
            atomic(name, Path(v['stage']).read_bytes(), v['mode'], Path(name)==WRAPPER)
        restart_subscription()
        check(j)
    except Exception:
        rollback(receipt)
        raise
    return {'applied': True, 'container_restarted': False, 'guard_seconds': 1200}


def main():
    action, directory = sys.argv[1:3]; receipt=Path(directory).resolve()
    assert receipt.parent==Path('/var/backups') and receipt.name.startswith('clash-usage-auto-'), 'private_receipt_required'
    assert receipt.is_dir(), 'existing_backup_required'
    if action=='prepare':result=prepare(receipt,json.load(sys.stdin))
    elif action=='apply':result=apply(receipt)
    elif action=='rollback':result=rollback(receipt)
    elif action=='check':check(json.loads((receipt/'usage-journal.json').read_text()));result={'rollback_precheck':True}
    elif action=='accept':
        check(json.loads((receipt/'usage-journal.json').read_text()));write(receipt/'USAGE_ACCEPTED.json',{'at':time.time()});result={'accepted':True}
    elif action=='guard':
        deadline=time.monotonic()+1200
        while time.monotonic()<deadline:
            if (receipt/'USAGE_ACCEPTED.json').exists() or (receipt/'USAGE_ROLLED_BACK.json').exists():return
            time.sleep(5)
        result=rollback(receipt)
    else:raise ValueError('unknown_action')
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception as error:
        # Never print exception text: it may contain a path or a private URL.
        print(json.dumps({'ok':False,'error_class':type(error).__name__}));sys.exit(1)
