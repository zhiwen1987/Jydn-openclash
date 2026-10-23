"""Independent frozen synthetic gates; never runs a browser or product server."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import threading
import unittest

import check_status_contract_outputs as originals

PINS = {
    'collector': (12, '525077090b05dae125d8f3cdc21ba8f8c998b27d88ad50c78ea2c1ed65c2f693'),
    'subscriptionDOM': (36, 'ad5fe9a1b5cc63e0cf38e50d537d815369313041347cb721eca5327cc3b61f82'),
    'frontend': (12, 'f631cf66f1842329b466bf0139c930409b9fb2d2d4ab9fe2a589050b0dfe1b03'),
    'pythonProjection': (12, 'ce6bbc4cf5dff4e6f047a465bbe94282b11e787c30b9e62d8dc2a81e6b939f11'),
    'artifactChecker': (8, 'da6a8fb45b108e2fbf605d3ac469ed40f69515ecafae376fe44a1b87b3db0622'),
}


def need(value):
    if not value:
        raise ValueError('diagnostic synthetic gate rejected')


def fingerprint(names):
    need(type(names) is list and names and all(type(n) is str and 0 < len(n) <= 256 for n in names))
    need(len(names) == len(set(names)))
    return len(names), hashlib.sha256('\n'.join(sorted(names)).encode()).hexdigest()


class BoundedText(io.StringIO):
    """Retain original text, never more than the public-artifact per-file cap."""
    def __init__(self):
        super().__init__(); self.size = 0; self.complete = True

    def write(self, value):
        raw = value.encode('utf-8', errors='strict')
        if self.size + len(raw) > originals.MAX_BYTES:
            self.complete = False
            raise ValueError('synthetic original output limit')
        self.size += len(raw)
        return super().write(value)


class RawStore:
    def __init__(self, root):
        root.mkdir(mode=0o700, exist_ok=False)
        self.root = root; self.files = {}; self.execution = {}

    def write(self, name, raw):
        need(name in originals.RAW_NAMES and name not in self.files
             and type(raw) is bytes and len(raw) <= originals.MAX_BYTES)
        # Old public archive deliberately rejects zero-byte files. Preserve the
        # true empty digest/size in the manifest, not an invented newline file.
        if raw:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
            fd = os.open(self.root / name, flags, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
        self.files[name] = raw

    def finish(self):
        self.write('execution.json', (json.dumps(dict(schema='chengwang.status-contract-execution/v1',
            groups=self.execution), separators=(',', ':')) + '\n').encode())
        need(set(self.files) == originals.RAW_NAMES)
        manifest = dict(schema='chengwang.status-contract-originals/v1', files=[dict(path=name,
            bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), stored=bool(raw))
            for name, raw in sorted(self.files.items())])
        raw = (json.dumps(manifest, separators=(',', ':')) + '\n').encode()
        need(0 < len(raw) <= originals.MAX_BYTES)
        fd = os.open(self.root / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)


def execute(args, store, pin):
    """Bound memory/file bytes while preserving failed combined stdout too."""
    captured = bytearray(); complete = True; outcome = 'RETURNED'; code = None
    process = None; reader = None; reader_failed = []
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def consume():
            try:
                while True:
                    chunk = process.stdout.read(65536)
                    if not chunk:
                        return
                    remaining = originals.MAX_BYTES - len(captured)
                    captured.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        reader_failed.append('OUTPUT_LIMIT'); process.kill(); return
            except Exception:
                reader_failed.append('RUNNER_ERROR')

        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            outcome = 'TIMED_OUT'; process.kill(); code = process.wait(timeout=5)
        reader.join(timeout=5)
        if reader.is_alive():
            outcome = 'RUNNER_ERROR'; complete = False
        if reader_failed:
            outcome = reader_failed[0]; complete = False
        if outcome != 'RETURNED':
            complete = False
    except Exception:
        outcome = 'RUNNER_ERROR'; complete = False
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=5)
    finally:
        if process is not None and (reader is None or not reader.is_alive()):
            process.stdout.close()
    store.write(originals.OUTPUTS[pin][0], bytes(captured))
    store.execution[pin] = dict(mode='SUBPROCESS', exitCode=code, outcome=outcome, captureComplete=complete)


class Recorded(unittest.TextTestResult):
    def __init__(self, *args, events):
        super().__init__(*args); self.events = events; self.runs = []; self.passes = []

    def record(self, event, test):
        self.events.write(json.dumps(dict(event=event, name=test.id()), separators=(',', ':')) + '\n')

    def startTest(self, test):
        self.record('RUN', test); self.runs.append(test.id()); super().startTest(test)

    def addSuccess(self, test):
        self.record('PASS', test); self.passes.append(test.id()); super().addSuccess(test)

    def addFailure(self, test, err):
        self.record('FAIL', test); super().addFailure(test, err)

    def addError(self, test, err):
        self.record('ERROR', test); super().addError(test, err)

    def addSkip(self, test, reason):
        self.record('SKIP', test); super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self.record('EXPECTED_FAILURE', test); super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self.record('UNEXPECTED_SUCCESS', test); super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.record('SUBTEST_ERROR', test)
        super().addSubTest(test, subtest, err)


def python_tests(base, name, pin, store):
    source = base / (name + '.py')
    stream, events = BoundedText(), BoundedText()
    outcome = 'RETURNED'
    try:
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        factory = lambda *args: Recorded(*args, events=events)
        result = unittest.TextTestRunner(stream=stream, descriptions=False, verbosity=2, resultclass=factory).run(
            unittest.defaultTestLoader.loadTestsFromModule(module))
        events.write(json.dumps(dict(event='SUMMARY', testsRun=result.testsRun, testsPassed=len(result.passes),
            failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
            expectedFailures=len(result.expectedFailures), unexpectedSuccesses=len(result.unexpectedSuccesses)),
            separators=(',', ':')) + '\n')
    except Exception:
        # No raw exception material escapes into the public summary. Existing
        # original unittest output remains in its own bounded synthetic log.
        outcome = 'RUNNER_ERROR'
    store.write(originals.OUTPUTS[pin][0], events.getvalue().encode())
    store.write(originals.OUTPUTS[pin][1], stream.getvalue().encode())
    store.execution[pin] = dict(mode='IN_PROCESS_UNITTEST', outcome=outcome,
                                captureComplete=bool(stream.complete and events.complete and outcome == 'RETURNED'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', required=True); parser.add_argument('--web-build', type=pathlib.Path, required=True)
    parser.add_argument('--report', type=pathlib.Path, required=True)
    args = parser.parse_args()
    base = pathlib.Path(__file__).resolve().parent
    source = base.parents[2]
    need(PINS == originals.PINS and not args.report.exists() and not args.report.is_symlink())
    store = RawStore(args.report.with_name(args.report.name + '.raw'))
    execute([args.node, '--test', '--test-reporter=tap',
        str(source / 'chengwang/tools/probe-browser/test-probe-status-diagnostics.mjs')], store, 'collector')
    execute([args.node, '--test', '--test-reporter=tap',
        str(source / 'chengwang/tools/subscription-browser/test-collect-subscription-dom.mjs')], store, 'subscriptionDOM')
    execute([args.node, str(args.web_build / 'tools/check-probe-status-observation.mjs')], store, 'frontend')
    python_tests(base, 'test_probe_status_diagnostics', 'pythonProjection', store)
    python_tests(base, 'test_check_status_diagnostic', 'artifactChecker', store)
    store.finish()
    # The PASS document is derived only after all five original outputs have
    # been retained, including failure transcripts. A failed input never emits it.
    report = originals.recompute(store.files)
    with args.report.open('xb') as output:
        output.write((json.dumps(report, separators=(',', ':')) + '\n').encode())
    print('STATUS_DIAGNOSTIC_CONTRACTS=PASS tests=80 skips=0 synthetic_only=true browser_e2e_proven=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('STATUS_DIAGNOSTIC_CONTRACTS=FAIL raw_input_suppressed=true') from None
