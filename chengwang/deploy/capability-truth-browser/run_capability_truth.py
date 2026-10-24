"""CI-only real product capability UI entry, with two closed profiles."""
import argparse
import importlib.util
import os
import pathlib
import re
import sys
import uuid


def load(repo, relative, name):
    spec = importlib.util.spec_from_file_location(name, repo / relative)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def main():
    parser = argparse.ArgumentParser()
    for name in ('repo', 'consumption-root', 'consumption-report', 'node', 'server', 'dist', 'build-report', 'output-dir'):
        parser.add_argument('--' + name, required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    parser.add_argument('--profile', required=True, choices=('default', 'backend_configured'))
    parser.add_argument('--fixture', default=None); parser.add_argument('--inner', action='store_true')
    options = parser.parse_args(); repo = options.repo.resolve(strict=True)
    S = load(repo, 'chengwang/deploy/browser-scene-supervisor/supervisor.py', 'capability_shared_supervisor')
    S.need(sys.platform == 'linux' and os.geteuid() == 0 and re.fullmatch('[a-f0-9]{40}', options.source_commit))
    M = load(repo, 'chengwang/deploy/browser-stream-matrix/run_matrix.py', 'capability_matrix_primitives'); N = M.load_native(repo)
    L = load(repo, 'chengwang/deploy/browser-scene-supervisor/lifecycle.py', 'capability_lifecycle_primitives')
    fixture = options.fixture or uuid.uuid4().hex; S.need(re.fullmatch('[a-f0-9]{32}', fixture))
    root = pathlib.Path('/tmp/chengwang-subscription-ui-' + fixture); bundle = pathlib.Path('/tmp/chengwang-subscription-ui-tools-' + fixture)
    key = S.select_key('capability_truth', profile=options.profile)
    if options.inner: return S.supervise_scene(options, repo, root, bundle, fixture, key, N, M, L)
    return S.run_scene_outer(options, repo, root, bundle, fixture, key, N, M, L)


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('CAPABILITY_TRUTH=REJECTED raw_input_suppressed=true') from None
