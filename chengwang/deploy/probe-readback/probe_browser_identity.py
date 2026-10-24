"""Independent identity sidecar; observation never proves patch ancestry."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

PREFIX = b'CW_PROBE_BROWSER_IDENTITY:'
MAX_LOG = 329728
BASE_FIELDS = {'schema', 'engine', 'fixtureId', 'browser', 'chrome'}
OBSERVATION_SCHEMA = 'chengwang.probe-browser-identity-observation/v1'
PUBLIC_SCHEMA = 'chengwang.probe-browser-identity/v1'
HELPERS = {
    'chengwang/deploy/probe-readback/probe_browser_identity.py',
    'chengwang/tools/probe-browser/browser-identity.mjs',
}
DRIVER_FIELDS = {'schema', 'engine', 'fixtureId', 'runtime', 'browserPluginUsed', 'mockedResponses',
    'injectedFetch', 'tlsBypass', 'chromeSandbox', 'realBrowser', 'responseBodyScope',
    'receivedClockResolution', 'normalTrust', 'chrome', 'tls', 'certificateChain', 'screenshotCount',
    'network', 'close', 'runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors',
    'assetErrors', 'forbiddenRequests', 'failedRequests', 'captureErrors'}


class Rejected(ValueError):
    def __init__(self): super().__init__('browser identity rejected')


def need(value):
    if not value: raise Rejected()


def integer(value, minimum=0, maximum=9007199254740991):
    need(type(value) is int and minimum <= value <= maximum)


def match(value, pattern):
    need(type(value) is str and re.fullmatch(pattern, value))


def exact(value, fields):
    need(type(value) is dict and set(value) == fields)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result); result[key] = value
    return result


def observation(value):
    exact(value, BASE_FIELDS)
    need(value['schema'] == OBSERVATION_SCHEMA and type(value['engine']) is str
         and value['engine'] in {'chrome-cdp', 'playwright'})
    match(value['fixtureId'], r'[a-f0-9]{32}')
    browser, chrome = value['browser'], value['chrome']
    exact(browser, {'product', 'revision', 'protocolVersion'})
    match(browser['product'], r'(?:Chrome|HeadlessChrome)/[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}')
    match(browser['revision'], r'@[a-f0-9]{40}'); match(browser['protocolVersion'], r'[0-9]{1,3}\.[0-9]{1,3}')
    exact(chrome, {'pid', 'startTicks', 'argvSHA256'})
    integer(chrome['pid'], 2); integer(chrome['startTicks'], 1); match(chrome['argvSHA256'], r'[a-f0-9]{64}')
    return value


def decode_line(line):
    need(type(line) is bytes and 0 < len(line) <= 1024 and line.startswith(PREFIX))
    need(all(32 <= byte <= 126 for byte in line))
    raw = line[len(PREFIX):].decode('ascii')
    try: value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, TypeError, RecursionError): raise Rejected() from None
    need(json.dumps(value, separators=(',', ':'), ensure_ascii=True) == raw)
    return observation(value)


def project(raw, commit, engine, fixture, copies):
    need(type(raw) is bytes and len(raw) <= MAX_LOG)
    match(commit, r'[a-f0-9]{40}'); match(fixture, r'[a-f0-9]{32}')
    need(type(engine) is str and engine in {'chrome-cdp', 'playwright'} and type(copies) is list)
    rows, rejected = [], 0
    for line in raw.splitlines():
        if not line.startswith(PREFIX): continue
        try:
            row = decode_line(line)
            need(row['engine'] == engine and row['fixtureId'] == fixture)
            if len(rows) < 2: rows.append(row)
            else: rejected += 1
        except Rejected: rejected += 1
    executable = None
    entries = [row for row in copies if type(row) is dict and row.get('path') == 'toolchain/chrome/chrome']
    if len(entries) == 1:
        entry = entries[0]
        exact(entry, {'path', 'bytes', 'sha256'}); integer(entry['bytes'], 1, 512 << 20)
        match(entry['sha256'], r'[a-f0-9]{64}')
        executable = dict(bytes=entry['bytes'], sha256=entry['sha256'])
    state = 'observed' if len(rows) == 1 and rejected == 0 and executable else 'missing' if not rows and not rejected else 'rejected'
    return dict(schema=PUBLIC_SCHEMA, sourceCommit=commit, engine=engine, fixtureId=fixture, state=state,
        observation=rows[0] if state == 'observed' else None, executable=executable,
        bindingScope='CDP_VERSION_WITH_TRUSTED_SUPERVISOR_BYTE_COPY',
        rawIdentityLines=len(rows) + rejected, browserAcceptanceProven=False, patchAncestryProven=False)


def verify(value, build, processes, driver, commit, engine):
    exact(value, {'schema', 'sourceCommit', 'engine', 'fixtureId', 'state', 'observation', 'executable',
                  'bindingScope', 'rawIdentityLines', 'browserAcceptanceProven', 'patchAncestryProven'})
    need(value['schema'] == PUBLIC_SCHEMA and value['sourceCommit'] == commit and value['engine'] == engine
         and value['state'] == 'observed' and value['rawIdentityLines'] == 1 and type(value['rawIdentityLines']) is int)
    match(commit, r'[a-f0-9]{40}'); match(value['fixtureId'], r'[a-f0-9]{32}')
    need(value['bindingScope'] == 'CDP_VERSION_WITH_TRUSTED_SUPERVISOR_BYTE_COPY'
         and value['browserAcceptanceProven'] is False and value['patchAncestryProven'] is False)
    row = observation(value['observation'])
    need(row['engine'] == engine and row['fixtureId'] == value['fixtureId'])
    for other in (build, processes):
        need(type(other) is dict and other.get('sourceCommit') == commit and other.get('production') is False)
    need(build.get('engine') == engine and build.get('fixtureId') == value['fixtureId'])
    copies = build.get('copiedInputs'); need(type(copies) is list)
    inputs = {}
    for item in copies:
        exact(item, {'path', 'bytes', 'sha256'}); need(type(item['path']) is str and item['path'] not in inputs)
        integer(item['bytes'], 1, 512 << 20); match(item['sha256'], r'[a-f0-9]{64}')
        inputs[item['path']] = item
    need(HELPERS | {'toolchain/chrome/chrome'} <= inputs.keys())
    exact(value['executable'], {'bytes', 'sha256'})
    need(value['executable'] == {key: inputs['toolchain/chrome/chrome'][key] for key in ('bytes', 'sha256')})
    integer(value['executable']['bytes'], 1, 512 << 20); match(value['executable']['sha256'], r'[a-f0-9]{64}')
    records = processes.get('records'); need(type(records) is list)
    need(all(type(item) is dict for item in records))
    chrome = [item for item in records if item.get('role') == 'chrome']; need(len(chrome) == 1)
    chrome = chrome[0]
    match(chrome.get('startTime'), r'[1-9][0-9]{0,19}'); integer(chrome.get('pid'), 2)
    match(chrome.get('argvSHA256'), r'[a-f0-9]{64}')
    need(row['chrome'] == dict(pid=chrome['pid'], startTicks=int(chrome['startTime']), argvSHA256=chrome['argvSHA256']))
    executable = processes.get('chromeExecutable')
    exact(executable, {'path', 'bytes', 'sha256', 'sourceScope'})
    need(chrome['exeSHA256'] == executable['sha256'] == value['executable']['sha256']
         and type(executable['bytes']) is int and executable['bytes'] == value['executable']['bytes'])
    argv = processes.get('chromeArgv'); need(type(argv) is list and 1 <= len(argv) <= 128)
    need(all(type(arg) is str and 0 < len(arg) <= 8192 and re.fullmatch(r'[\x20-\x7e]+', arg) for arg in argv))
    forbidden = {'--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors',
        '--allow-insecure-localhost', '--disable-web-security', '--unsafely-treat-insecure-origin-as-secure'}
    need(argv[0] == executable['path'] and not any(arg.split('=', 1)[0] in forbidden for arg in argv)
         and hashlib.sha256(b''.join(arg.encode() + b'\0' for arg in argv)).hexdigest() == chrome['argvSHA256'])
    exact(driver, DRIVER_FIELDS)
    need(driver.get('fixtureId') == value['fixtureId'] and driver.get('engine') == engine
         and driver.get('realBrowser') == row['browser']['product'])
    need(all(driver['chrome'][key] == row['chrome'][key] for key in ('pid', 'startTicks', 'argvSHA256')))
    return dict(schema='chengwang.probe-browser-identity-verification/v1', sourceCommit=commit,
        engine=engine, fixtureId=value['fixtureId'], browser=row['browser'], executable=value['executable'],
        identityFieldsMatched=True, processBindingVerified=False, requiredSourceHelpers=sorted(HELPERS),
        browserAcceptanceProven=False, patchAncestryProven=False, production=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence-root', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True); parser.add_argument('--engine', required=True)
    parser.add_argument('--report', required=True, type=pathlib.Path)
    args = parser.parse_args()
    import check_probe_readback as B
    import check_probe_browser as legacy
    root = args.evidence_root.resolve(strict=True); report = args.report.resolve()
    need(not report.is_relative_to(root))
    raw = B.read_file(root / 'browser-identity.json', 8192)
    build = B.decoded(B.read_file(root / 'browser/browser-build.json'), source_manifest=True)
    processes = B.decoded(B.read_file(root / 'browser/browser-processes.json'))
    driver = B.decoded(B.read_file(root / 'browser/browser-driver.json'))
    # Recompute original backend/build/process evidence, not a stored PASS flag.
    # Deliberately do not call validate_driver: a browser request failure must
    # remain a failure of the original browser gate without hiding its identity.
    native = B.verify(root / 'backend', args.source_commit)
    _, captures = legacy.capture_names(args.engine)
    own_names = captures | {'browser-captures.json', 'browser-driver.json', 'browser-build.json', 'browser-processes.json'}
    browser_dir = root / 'browser'
    need({p.name for p in browser_dir.iterdir()} == own_names | {'web'})
    originals = {name: B.read_file(browser_dir / name, 8 << 20) for name in own_names}
    need(build == B.decoded(originals['browser-build.json'], source_manifest=True) and processes == B.decoded(originals['browser-processes.json'])
         and driver == B.decoded(originals['browser-driver.json']))
    isolation = B.decoded(B.read_file(root / 'backend' / (B.PREFIX + 'isolation.json')), source_manifest=True)
    legacy.validate_build(browser_dir, build, isolation, args.source_commit, native['fixtureId'], args.engine)
    legacy.validate_processes(processes, driver, build, isolation, originals, args.source_commit, native['fixtureId'], args.engine)
    result = verify(B.decoded(raw), build, processes, driver, args.source_commit, args.engine)
    copies = {row['path']: row for row in build['copiedInputs']}
    before = build['sourceFilesBefore']; need(before == build['sourceFilesAfter'])
    sources = {row['path']: row for row in before}; need(len(sources) == len(before))
    for name in HELPERS:
        original = subprocess.check_output(['git', 'show', args.source_commit + ':' + name], stderr=subprocess.DEVNULL)
        need(len(original) == copies[name]['bytes'] == sources[name]['bytes'])
        need(hashlib.sha256(original).hexdigest() == copies[name]['sha256'] == sources[name]['sha256'])
    validator_path = 'chengwang/deploy/probe-readback/check_probe_browser.py'
    validator_original = subprocess.check_output(['git', 'show', args.source_commit + ':' + validator_path], stderr=subprocess.DEVNULL)
    need(validator_original == B.read_file(pathlib.Path(legacy.__file__)))
    result['legacyProcessValidatorSHA256'] = B.sha(validator_original)
    result['sourceHelpersVerified'] = sorted(HELPERS)
    result['processBindingVerified'] = True
    result['processValidationScope'] = 'ORIGINAL_BACKEND_BUILD_AND_PROCESS_GATES_NOT_BROWSER_ERROR_GATE'
    result['originalIdentitySHA256'] = B.sha(raw)
    with report.open('xb') as output: output.write((json.dumps(result, separators=(',', ':')) + '\n').encode())
    print('BROWSER_IDENTITY=VERIFIED patch_ancestry_proven=false browser_acceptance_proven=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('BROWSER_IDENTITY=REJECTED raw_input_suppressed=true') from None
