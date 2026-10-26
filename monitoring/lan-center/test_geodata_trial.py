"""Trial trust boundaries and recovery: no network or production state in tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

if os.name == 'nt':
    raise unittest.SkipTest('Linux flock worker; run on Linux host or CI')

spec = importlib.util.spec_from_file_location('geodata_trial', Path(__file__).with_name('geodata_trial.py'))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


class FakeFetcher:
    def __init__(self):
        self.data = {name: (name.encode()*13000)[:24000] for name in trial.FILES}
        self.calls = []
        self.fail = False

    def metadata(self):
        return {'name': 'test release', 'published_at': '2026-10-26T00:00:00Z',
                'assets': [{'name': n, 'size': len(b), 'digest': 'sha256:'+hashlib.sha256(b).hexdigest(),
                            'browser_download_url': 'https://github.com/'+trial.REPO+'/releases/download/latest/'+n}
                           for n, b in self.data.items()]}

    def fetch(self, url, target, limit=trial.MAX_DATA):
        self.calls.append(url)
        if '/releases/tags/' in url:
            target.write_text(json.dumps(self.metadata()))
        else:
            if self.fail:
                raise RuntimeError('upstream_fetch_failed')
            target.write_bytes(self.data[url.rsplit('/', 1)[-1]])


class TrialTests(unittest.TestCase):
    def test_api_rate_limit_falls_back_to_publisher_checksums(self):
        fetcher = FakeFetcher()
        def fetch(url, target, limit=trial.MAX_DATA):
            if '/releases/tags/' in url:
                raise RuntimeError('upstream_fetch_failed_curl_22_http_403')
            name = url.rsplit('/', 1)[-1].removesuffix('.sha256sum')
            target.write_text(hashlib.sha256(fetcher.data[name]).hexdigest()+'  '+name+'\n')
        with tempfile.TemporaryDirectory() as d, patch.object(fetcher, 'fetch', side_effect=fetch):
            release, assets = trial.source_metadata(fetcher, Path(d))
            self.assertEqual(set(assets), set(trial.FILES))
            self.assertIsNone(release['published_at'])
            self.assertEqual(release['metadata_mode'], 'publisher_checksum_assets')

    def test_one_changed_file_reuses_other_verified_assets(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            core = root/'core'
            core.write_bytes(b'fake core')
            fetcher = FakeFetcher()
            with patch.object(trial, 'CORE_SHA', trial.digest(core)), patch.object(trial, 'native_check', return_value={}):
                trial.collect(root, core, fetcher, lambda: ['cn'])
                before = len(fetcher.calls)
                fetcher.data['geosite.dat'] = b'updated'*5000
                trial.collect(root, core, fetcher, lambda: ['cn'])
                self.assertEqual(len(fetcher.calls)-before, 2)  # metadata plus changed data only

    def test_public_metadata_fallback_does_not_change_production_proxy_or_expose_auth(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)/'metadata.json'
            calls = []
            def run(command, **kwargs):
                self.assertNotIn('test-user:test-password', command)
                calls.append(kwargs['input'])
                if len(calls) == 1:
                    return SimpleNamespace(returncode=22, stdout='403')
                target.write_bytes(b'{}')
                return SimpleNamespace(returncode=0, stdout='200')
            with patch.object(trial.subprocess, 'run', side_effect=run):
                trial.Fetcher('http://127.0.0.1:7893', 'test-user:test-password').fetch('https://api.github.com/test', target)
            self.assertIn('proxy-user', calls[0])
            self.assertNotIn('proxy-user', calls[1])
            self.assertIn('proxy = ""', calls[1])

    def test_untrusted_redirect_host_or_path_and_duplicate_rejected(self):
        for url in ['http://github.com/unsafe', 'https://github.com@127.0.0.1/unsafe',
                    'https://evil.invalid/unsafe', 'https://github.com/another/repo/geosite.dat']:
            metadata = FakeFetcher().metadata()
            metadata['assets'][0]['browser_download_url'] = url
            with self.assertRaisesRegex(ValueError, 'invalid_upstream_asset'):
                trial.metadata_assets(metadata)
        metadata = FakeFetcher().metadata()
        metadata['assets'].append(metadata['assets'][0])
        with self.assertRaises(ValueError):
            trial.metadata_assets(metadata)

    def test_incomplete_unbounded_and_unhashed_release_rejected(self):
        for change in ('missing', 'oversized', 'digest'):
            metadata = FakeFetcher().metadata()
            if change == 'missing':
                metadata['assets'].pop()
            elif change == 'oversized':
                metadata['assets'][0]['size'] = trial.MAX_DATA+1
            else:
                metadata['assets'][0]['digest'] = ''
            with self.assertRaises(ValueError):
                trial.metadata_assets(metadata)

    def test_fixture_has_no_production_listeners_nodes_or_update_paths(self):
        value = trial.fixture(['cn', 'google'], False)
        self.assertEqual(value['mixed-port'], 0)
        self.assertFalse(value['dns']['enable'])
        self.assertFalse(value['geo-auto-update'])
        self.assertEqual(value['proxy-groups'], [])
        self.assertTrue(all(v.endswith(',REJECT') for v in value['rules']))
        self.assertTrue(all('127.0.0.1:9' in v for v in value['geox-url'].values()))

    def test_category_input_cannot_escape_configuration(self):
        with self.assertRaises(ValueError):
            trial.categories_from_rules({'rules': [{'type': 'GeoSite', 'payload': 'cn\nMATCH,DIRECT'}]})

    def test_unchanged_data_skips_asset_download_and_native_work(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            core = root/'core'
            core.write_bytes(b'fake core')
            fetcher = FakeFetcher()
            with patch.object(trial, 'CORE_SHA', trial.digest(core)), patch.object(trial, 'native_check', return_value={}) as native:
                value = trial.collect(root, core, fetcher, lambda: ['cn', 'google'])
                self.assertFalse(value['production_applied'])
                self.assertEqual(native.call_count, 2)
                count = len(fetcher.calls)
                again = trial.collect(root, core, fetcher, lambda: ['cn', 'google'])
                self.assertTrue(again['unchanged'])
                self.assertEqual(len(fetcher.calls), count+1)
                self.assertEqual(native.call_count, 2)

    def test_failed_new_candidate_preserves_previous_verified_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            core = root/'core'
            core.write_bytes(b'fake core')
            fetcher = FakeFetcher()
            with patch.object(trial, 'CORE_SHA', trial.digest(core)), patch.object(trial, 'native_check', return_value={}):
                value = trial.collect(root, core, fetcher, lambda: ['cn'])
                before = (root/'candidate.json').read_bytes()
                fetcher.data['geosite.dat'] = b'new'*10000
                fetcher.fail = True
                with self.assertRaisesRegex(RuntimeError, 'upstream_fetch_failed'):
                    trial.collect(root, core, fetcher, lambda: ['cn'])
                self.assertEqual((root/'candidate.json').read_bytes(), before)
                old = root/'candidates'/value['id']/'GeoSite.dat'
                self.assertEqual(trial.digest(old), value['assets']['geosite.dat']['sha256'])

    def test_corrupt_cached_candidate_is_repaired_and_revalidated(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            core = root/'core'
            core.write_bytes(b'fake core')
            fetcher = FakeFetcher()
            with patch.object(trial, 'CORE_SHA', trial.digest(core)), patch.object(trial, 'native_check', return_value={}) as native:
                value = trial.collect(root, core, fetcher, lambda: ['cn'])
                path = root/'candidates'/value['id']/'GeoSite.dat'
                path.write_bytes(b'corrupted')
                repaired = trial.collect(root, core, fetcher, lambda: ['cn'])
                self.assertFalse(repaired.get('unchanged', False))
                self.assertEqual(native.call_count, 4)
                self.assertEqual(path.read_bytes(), fetcher.data['geosite.dat'])


if __name__ == '__main__':
    unittest.main()
