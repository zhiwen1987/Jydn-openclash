"""Build a credential-free offline bundle from pinned, reviewed inputs.

No production connection or deployment occurs in this script. Docker archive
must be produced by the documented audited image build, never docker commit.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parent
REPO=ROOT.parent
CORE_SHA='59198acb9b851f59ab328396684bc8c1ec70c432f8f1cd035c27ad2fdf549b08'
BASE_ID='sha256:092bdbda0b61b4056fc08cacf7cf63621e302d7b657602e884f0dc3a817889f7'
PYTHON_SHA='9e35319bffedab8b36ad44d8f377cb4f1733bcec257a0b6d04d94f01486ddb38'

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        while block:=f.read(1048576):h.update(block)
    return h.hexdigest()

def copy(source,target):
    target=Path(target);target.parent.mkdir(parents=True,exist_ok=True)
    if target.suffix=='.sh':target.write_bytes(Path(source).read_bytes().replace(b'\r\n',b'\n'))
    else:shutil.copyfile(source,target)

def tar_directory(source,target):
    with target.open('wb') as out,gzip.GzipFile(fileobj=out,mode='wb',mtime=0,compresslevel=2) as gz,tarfile.open(fileobj=gz,mode='w|') as archive:
        for path in sorted(source.rglob('*')):
            if not path.is_file():continue
            info=archive.gettarinfo(str(path),str(path.relative_to(source)).replace('\\','/'))
            info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0;info.mode=0o600
            with path.open('rb') as f:archive.addfile(info,f)

def context(capture):
    output=ROOT/'.build/context';output.mkdir(parents=True,exist_ok=True)
    assert sha(capture/'router/core')==CORE_SHA
    for path in (ROOT/'runtime').rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:copy(path,output/'runtime'/path.relative_to(ROOT/'runtime'))
    for name in ['node_links.py','local_source.py','local_web.py','editor.html','editor.js']:
        copy(REPO/'monitoring/lan-center/local-subscription'/name,output/'local-subscription'/name)
    copy(capture/'router/core',output/'core');copy(ROOT/'Dockerfile',output/'Dockerfile')
    tar_directory(output,ROOT/'.build/context.tar.gz')
    print(json.dumps({'context':str(output),'archive':str(ROOT/'.build/context.tar.gz'),'base_image':BASE_ID}))

def bundle(args):
    capture=args.capture.resolve();destination=ROOT/'dist'/('clash-stack-'+args.version)
    assert sha(capture/'router/core')==CORE_SHA
    downloads=ROOT/'.build/downloads';lock=json.loads((downloads/'dependencies.lock.json').read_text(encoding='utf-8'))
    verified={r['path']:r['sha256'] for r in lock['wheels']}
    for wheel in downloads.glob('wheels-*/*.whl'):
        assert sha(wheel)==verified[str(wheel.relative_to(downloads)).replace('\\','/')]
    if destination.exists():raise SystemExit('Output already exists; choose a new version or explicit empty destination')
    destination.mkdir(parents=True)
    for folder in ('stack','agents'):
        for p in (ROOT/folder).rglob('*.py' if folder=='stack' else '*'):
            if p.is_file() and '__pycache__' not in p.parts:copy(p,destination/folder/p.relative_to(ROOT/folder))
    for name in ('clash_stack.py','start.ps1','开始安装.cmd','install.sh','README.zh-CN.md','RECOVERY.zh-CN.md','ACCEPTANCE.zh-CN.md','NOTICE.md'):
        copy(ROOT/name,destination/name)
    # Keep the offline package self-contained: repository installer documents
    # live one directory deeper, so adapt only their Markdown link prefixes.
    (destination/'README.md').write_text((REPO/'README.md').read_text(encoding='utf-8-sig').replace('](installer/',']('),encoding='utf-8')
    for path in (REPO/'docs').glob('*.md'):
        target=destination/'docs'/path.name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(path.read_text(encoding='utf-8-sig').replace('](../installer/','](../'),encoding='utf-8')
    for name in ('README.zh-CN.md','ACCEPTANCE.zh-CN.md'):
        target=destination/name
        target.write_text(target.read_text(encoding='utf-8-sig').replace('](../docs/','](docs/'),encoding='utf-8')
    router=destination/'payload/router'
    for name in ('template.json','strict_custom.rb','strict-custom-policy.json','router_compile.rb'):copy(ROOT/'runtime'/name,router/name)
    copy(capture/'router/core',router/'core')
    for source,name in [(ROOT/'runtime/upstream/node-capability.py','node-capability.py'),(ROOT/'runtime/upstream/healthcheck.sh','healthcheck.sh'),(ROOT/'runtime/portable_subscriptions.py','subscription-controller.py')]:
        copy(source,destination/'payload/center'/name)
    for path in (capture/'router/rules').rglob('*'):
        if path.is_file():copy(path,router/'rules'/path.relative_to(capture/'router/rules'))
    payload_hashes={str(p.relative_to(destination)).replace('\\','/'):sha(p) for p in (destination/'payload').rglob('*') if p.is_file()}
    # The archive has a payload/ prefix, matching the remote extraction contract.
    scratch=ROOT/'.build'/('tar-root-'+args.version);scratch.mkdir(parents=True,exist_ok=False)
    shutil.copytree(destination/'payload',scratch/'payload',dirs_exist_ok=True)
    tar_directory(scratch,destination/'payload.tar.gz')
    copy(args.image,destination/'clash-center.tar.gz')
    assert sha(downloads/'python-win313.zip')==PYTHON_SHA
    with zipfile.ZipFile(downloads/'python-win313.zip') as z:z.extractall(destination/'runtime/win64')
    pth=destination/'runtime/win64/python313._pth'
    pth.write_text('python313.zip\n.\n../../vendor/win-cp313\n',encoding='ascii')
    linux_wheels={}
    for wheels in downloads.glob('wheels-linux-*'):
        for wheel in wheels.glob('*.whl'):linux_wheels.setdefault(wheel.name,[]).append(wheel)
    shared={name for name,paths in linux_wheels.items() if len(paths)>1}
    extracted_shared=set()
    for wheels in downloads.glob('wheels-*'):
        tag=wheels.name.replace('wheels-','').replace('win313','win-cp313');vendor=destination/'vendor'/tag;vendor.mkdir(parents=True)
        for wheel in wheels.glob('*.whl'):
            target=vendor
            if tag.startswith('linux-') and wheel.name in shared:
                if wheel.name in extracted_shared:continue
                target=destination/'vendor/linux-common';target.mkdir(exist_ok=True)
                extracted_shared.add(wheel.name)
            with zipfile.ZipFile(wheel) as z:z.extractall(target)
    sources=destination/'sources';sources.mkdir()
    copy(downloads/'mihomo-source.tar.gz',sources/'mihomo-daf3ad03021cca6031f4a7303ca6d861a14d5a16.tar.gz')
    tar_directory(ROOT/'.build/context',sources/'center-build-context.tar.gz')
    # Initial seed only: no production databases, URLs, accounts or node secrets.
    copy(downloads/'dependencies.lock.json',destination/'sources/dependencies.lock.json')
    files={str(p.relative_to(destination)).replace('\\','/'):sha(p) for p in destination.rglob('*') if p.is_file()}
    manifest={'schema':1,'version':args.version,'platform':'linux/amd64','image_id':args.image_id,'base_image_id':BASE_ID,'kuma_version':args.kuma_version,'core_sha256':CORE_SHA,'files':files,'payload_files':payload_hashes,'payload_sha256':files['payload.tar.gz'],'image_archive_sha256':files['clash-center.tar.gz'],'router_files':[str(p.relative_to(router)).replace('\\','/') for p in router.rglob('*') if p.is_file()],'required_free_bytes':6*1024**3,'source_commit':args.commit,'assurance':'installation_acceptance_only_not_business_availability'}
    (destination/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    sums=''.join(h+'  '+name+'\n' for name,h in files.items())+sha(destination/'manifest.json')+'  manifest.json\n'
    (destination/'SHA256SUMS').write_text(sums,encoding='utf-8')
    print(json.dumps({'bundle':str(destination),'file_count':len(files),'image_bytes':args.image.stat().st_size}))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['context','bundle']);parser.add_argument('--capture',type=Path,default=ROOT/'.build/capture');parser.add_argument('--version',default='0.1.0-rc1');parser.add_argument('--image',type=Path);parser.add_argument('--image-id');parser.add_argument('--kuma-version',required=False);parser.add_argument('--commit',default='uncommitted')
    args=parser.parse_args();context(args.capture) if args.action=='context' else bundle(args)
