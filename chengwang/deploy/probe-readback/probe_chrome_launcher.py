#!/usr/bin/python3 -I
"""CI-only Chrome child/wait witness, used by both native automation paths.

Playwright's public close API does not expose Chrome's wait status. This small
launcher preserves its protocol descriptors, records a gated child identity,
and publishes only that child's actual wait result. It is not a sandbox or a
production process supervisor.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys


class Rejected(Exception):
    pass


def demand(value):
    if not value:
        raise Rejected()


def native_module():
    parent = pathlib.Path(__file__).resolve().parent
    path = parent / ('runner' if pathlib.Path(__file__).name == 'chrome-launcher'
                     else 'run_probe_readback.py')
    loader = importlib.machinery.SourceFileLoader('probe_chrome_native_helpers', str(path))
    specification = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(specification)
    loader.exec_module(module)
    return module


def validate_config(value, bundle):
    demand(type(value) is dict and set(value) == {'schema', 'engine', 'root', 'chrome'})
    match = re.fullmatch(r'/tmp/chengwang-probe-harness-([a-f0-9]{32})', str(bundle))
    demand(match is not None and value['schema'] == 'chengwang.probe-browser-config/v1'
           and value['engine'] in ('chrome-cdp', 'playwright')
           and value['root'] == '/tmp/chengwang-probe-readback-' + match[1])
    chrome = value['chrome']
    demand(type(chrome) is str and chrome.startswith('/') and '..' not in pathlib.PurePosixPath(chrome).parts
           and str(pathlib.PurePosixPath(chrome)) == chrome)
    return match[1], pathlib.Path(value['root'])


def validate_arguments(arguments, profile):
    demand(type(arguments) is list and 0 < len(arguments) <= 128)
    demand(all(type(arg) is str and 0 < len(arg) <= 8192 and '\0' not in arg for arg in arguments))
    demand(sum(map(len, arguments)) <= 65536)
    profiles = [arg for arg in arguments if arg.startswith('--user-data-dir')]
    demand(profiles == ['--user-data-dir=' + str(profile)])
    forbidden = ('--ignore-certificate-errors', '--ignore-certificate-errors-spki-list', '--ignore-ssl-errors', '--allow-insecure-localhost',
                 '--disable-web-security', '--unsafely-treat-insecure-origin-as-secure')
    demand(not any(arg.split('=', 1)[0] in forbidden for arg in arguments))
    demand('--no-sandbox' in arguments)


def start_ticks(pid):
    raw = pathlib.Path('/proc', str(pid), 'stat').read_text()
    number = int(raw[raw.rfind(')') + 2:].split()[19])
    demand(number > 0)
    return number


def main(arguments=None):
    child = None
    try:
        demand(sys.platform.startswith('linux') and os.geteuid() == os.getegid() == 10001
               and 'HOME' not in os.environ)
        backend = native_module()
        bundle = pathlib.Path(__file__).resolve().parent
        raw, info = backend.stable_read(bundle / 'browser-config.json', 16384, mode=0o440)
        demand(info.st_uid == 0 and info.st_gid == 10001)
        config = backend.decode(raw)
        fixture, root = validate_config(config, bundle)
        profile = root / 'browser/chrome-profile'
        arguments = sys.argv[1:] if arguments is None else arguments
        validate_arguments(arguments, profile)
        chrome = backend.checked_path(config['chrome'])
        executable, executable_info = backend.stable_read(chrome, 512 << 20)
        demand(executable[:4] == b'\x7fELF' and executable_info.st_uid == 0
               and not stat.S_IMODE(executable_info.st_mode) & 0o022)
        environment = dict(backend.BASE_ENV)
        environment.update({'XDG_DATA_HOME': str(root / 'browser/home/.local/share'),
                            'XDG_CONFIG_HOME': str(profile / 'config'),
                            'XDG_CACHE_HOME': str(profile / 'cache'),
                            'TMPDIR': str(root / 'browser/tmp')})
        fontconfig = bundle / 'fonts/fonts.conf'
        if fontconfig.is_file():
            environment['FONTCONFIG_FILE'] = str(fontconfig)

        def interrupted(_signum, _frame):
            raise Rejected()
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        # FDs 3/4 carry Playwright's real debugging pipe. Do not replace or
        # close them. No protocol bytes pass through this supervisor's logs.
        gate = 'IFS= read -r launch_gate && test "$launch_gate" = start || exit 78; exec "$@"'
        child = subprocess.Popen(['/usr/bin/bash', '--noprofile', '--norc', '-c', gate,
                                  'chengwang-probe-chrome', str(chrome), *arguments],
                                 stdin=subprocess.PIPE, close_fds=False,
                                 start_new_session=True, env=environment)
        ticks = start_ticks(child.pid)
        demand(os.getpgid(child.pid) == os.getsid(child.pid) == child.pid)
        record = {'pid': child.pid, 'startTicks': ticks, 'uid': 10001, 'profile': str(profile)}
        backend.publish_atomic(root / 'browser/chrome-process.private.json', backend.canonical(record) + b'\n', 0o600)
        child.stdin.write(b'start\n')
        child.stdin.close()
        code = child.wait(timeout=330)
        result = {'schema': 'chengwang.probe-chrome-exit/v1', 'engine': config['engine'],
                  'fixtureId': fixture, 'pid': child.pid, 'startTicks': ticks,
                  'exitCode': code, 'joined': True, 'forced': False}
        backend.publish_atomic(root / 'browser/chrome-exit.private.json', backend.canonical(result) + b'\n', 0o600)
        demand(code == 0)
        return 0
    except Exception:
        # Chrome/Playwright may include arguments in their own errors. Never
        # stringify an exception, CLI argument, environment or private record.
        sys.stderr.write('PROBE_CHROME_LAUNCHER=FAIL raw_input_suppressed=true\n')
        return 1
    finally:
        if child is not None and child.poll() is None:
            if child.stdin is not None and not child.stdin.closed:
                child.stdin.close()  # Unreleased gate exits without Chrome.
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                descriptor = os.pidfd_open(child.pid)
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                    try:
                        child.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        child.wait(timeout=3)
                finally:
                    os.close(descriptor)


if __name__ == '__main__':
    raise SystemExit(main())
