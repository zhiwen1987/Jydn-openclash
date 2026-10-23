"""Frozen feedback helper transcripts, not real rendered notice acceptance."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location('feedback_test_event_primitives',
    Path(__file__).with_name('check_remote_synthetic.py'))
H = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(H)
PYTHON = {
    'feedback-projection': ('test_feedback_projection', 'FeedbackProjectionContracts', 16,
                           '5153a2a2a16431c969fbc94f705efb4af90f437274b76cd35d47fd142ff8d2da'),
    'feedback-checker': ('test_check_handoff_feedback', 'HandoffFeedbackVerifierContracts', 20,
                        '788deffda1fb70aa2c1febc1113a507791a2162b8748d9cd4472483ef48f5a3b'),
}
NODE_COUNT = 24
NODE_NAMES_SHA = '0faa2544102d1f91cd0ee4340fa87fb802cd666582e132ae210774df6a819e3b'


def verify(evidence):
    suites = {}
    for filename, (module, classname, count, pin) in PYTHON.items():
        raw, text = H.original(evidence, filename + '.log')
        tree = ast.parse(Path(__file__).with_name(module + '.py').read_bytes())
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                   and any(isinstance(base, ast.Attribute) and base.attr == 'TestCase' for base in node.bases)]
        H.need(len(classes) == 1 and classes[0].name == classname)
        names = sorted(method.name for method in classes[0].body
                       if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith('test_'))
        H.python_events(text, module, classname, names, count, pin)
        suites[filename] = dict(tests=count, passed=count, skipped=0,
            namesSHA256=pin, originalSHA256=H.sha(raw))
    raw, text = H.original(evidence, 'feedback-node.tap')
    H.node_events(text, NODE_COUNT, NODE_NAMES_SHA)
    suites['feedback-node'] = dict(tests=NODE_COUNT, passed=NODE_COUNT, skipped=0,
        namesSHA256=NODE_NAMES_SHA, originalSHA256=H.sha(raw))
    return suites


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=Path)
    options = parser.parse_args(); H.need(re.fullmatch('[a-f0-9]{40}', options.source_commit))
    suites = verify(options.evidence)
    value = dict(schema='chengwang.handoff-feedback-synthetic/v1',sourceCommit=options.source_commit,
        suites=suites,tests=sum(suite['tests'] for suite in suites.values()),skipped=0,
        previous498Replaced=False,frontendVitestRun=False,realNoticeRepairProven=False,
        browserStarted=False,runtime=False,production=False,
        scope='SYNTHETIC_FEEDBACK_CONTRACTS_NOT_REAL_NOTICE_OR_PRODUCT_ACCEPTANCE')
    with options.report.open('xb') as target:
        target.write((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode())
    print('HANDOFF_FEEDBACK_SYNTHETIC=PASS tests='+str(value['tests'])+' skips=0 browser_started=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('HANDOFF_FEEDBACK_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
