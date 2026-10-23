"""Frozen helper transcripts only: never remote/UI/production acceptance."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location('handoff_test_event_primitives',
    Path(__file__).with_name('check_remote_synthetic.py'))
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

# Pre-CI declarations. Unset pins deliberately reject; never learn these from CI.
PYTHON = {
    'handoff-fixture': ('test_handoff_negative_fixture', 'HandoffNegativeFixtureContracts', 16,
                        'd768e5cb730edb01be476f072f5a3f8325519969d4e86efc5e42f26a6e75be92'),
    'handoff-checker': ('test_check_handoff_negative_ui', 'HandoffNegativeVerifierContracts', 32,
                        '45e79b7f9e14c9f3357e0c0ad64b7530ed631e23db225753198090503c6f9d13'),
    'handoff-synthetic-checker': ('test_check_handoff_negative_synthetic', 'HandoffNegativeSyntheticContracts', 12,
                                  '8a91e133a566436c164f72e387758b37840062ebf54696135751cec7cd87ea3c'),
}
NODE_COUNT = 48
NODE_NAMES_SHA = '62550e3a811d1f717c585de07911f855a01b0de470d013ed45781cd72897c3ce'


def verify(evidence):
    suites = {}
    for filename, (module, classname, count, pin) in PYTHON.items():
        raw, text = H.original(evidence, filename + '.log')
        tree = ast.parse(Path(__file__).with_name(module + '.py').read_bytes())
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                   and any(isinstance(base, ast.Attribute) and base.attr == 'TestCase' for base in node.bases)]
        H.need(len(classes) == 1 and classes[0].name == classname)
        names = sorted(method.name for method in classes[0].body
                       if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                       and method.name.startswith('test_'))
        H.python_events(text, module, classname, names, count, pin)
        suites[filename] = dict(tests=count, passed=count, skipped=0,
                               namesSHA256=pin, originalSHA256=H.sha(raw))
    raw, text = H.original(evidence, 'handoff-node.tap')
    H.node_events(text, NODE_COUNT, NODE_NAMES_SHA)
    suites['handoff-node'] = dict(tests=NODE_COUNT, passed=NODE_COUNT, skipped=0,
                                namesSHA256=NODE_NAMES_SHA, originalSHA256=H.sha(raw))
    return suites


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--report', required=True, type=Path)
    options = parser.parse_args()
    H.need(re.fullmatch('[a-f0-9]{40}', options.source_commit))
    suites = verify(options.evidence)
    value = dict(schema='chengwang.handoff-negative-ui-synthetic/v1',
        sourceCommit=options.source_commit, suites=suites,
        tests=sum(suite['tests'] for suite in suites.values()), skipped=0,
        previous84Replaced=False, previous76Replaced=False, remote86Replaced=False,
        navigation58Replaced=False, dependencies86Replaced=False,
        browserStarted=False, samplerStarted=False, wireStarted=False,
        runtime=False, production=False,
        scope='SYNTHETIC_CONTRACTS_NOT_REAL_HANDOFF_NEGATIVE_OR_PRODUCT_ACCEPTANCE')
    with options.report.open('xb') as target:
        target.write((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('HANDOFF_NEGATIVE_SYNTHETIC=PASS tests=' + str(value['tests'])
          + ' skips=0 browser_started=false sampler_started=false wire_started=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('HANDOFF_NEGATIVE_SYNTHETIC=REJECTED raw_input_suppressed=true') from None
