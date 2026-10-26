"""Initialize only missing new-site documents, then run the existing supervisor."""
import json
import os
from pathlib import Path
import subprocess


def main():
    os.umask(0o077)
    data=Path('/data');data.mkdir(parents=True,exist_ok=True)
    sources=data/'subscription-sources.json'
    if not sources.exists():sources.write_text(json.dumps({'sources':[]}))
    policy=data/'route-quality-policy.json'
    if not policy.exists():policy.write_text(json.dumps({'enabled':True,'manual_override_seconds':0}))
    setup=data/'setup-kuma.private.json'
    if setup.exists():subprocess.Popen(['node','/setup_kuma.js'],start_new_session=True)
    os.execv('/usr/bin/python3',['/usr/bin/python3','-B','/unified_runtime.py'])


if __name__=='__main__':main()
