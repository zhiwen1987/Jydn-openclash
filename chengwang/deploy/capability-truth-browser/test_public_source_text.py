"""Independent CPU source-text boundary tests, never real-browser evidence."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('retained_capability_test_factories', HERE / 'test_check_capability_truth.py')
LEGACY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEGACY)
C = LEGACY.C
CONTRACT = LEGACY.CONTRACT
ROOT = HERE.parents[2]
REGISTRY = ROOT / 'chengwang/internal/capability/registry.go'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def by_id(value, key):
    return next(item for item in value['capabilities'] if item['id'] == key)


def configured_report(source_texts):
    value = copy.deepcopy(LEGACY.report('backend_configured'))
    item = by_id(value, 'real_authentication')
    item['evidence'] = [source_texts[('evidence', 0)]]
    item['limitations'] = [source_texts[('limitations', 0)], 'Synthetic CPU-only additional limitation']
    return value


class PublicSourceTextContracts(unittest.TestCase):
    def setUp(self):
        self.registry = REGISTRY.read_bytes()
        self.source_texts = C.configured_identity_source_texts(self.registry)
        self.value = configured_report(self.source_texts)
        C.capability(CONTRACT, encoded(self.value), 'backend_configured')

    def fence(self, value=None, *, profile='backend_configured', source_texts=None):
        return C.public_body_fence(CONTRACT, encoded(self.value if value is None else value), 'CAPABILITIES', profile,
                                   self.source_texts if source_texts is None else source_texts)

    def rejects(self, function, *args, **kwargs):
        with self.assertRaises((ValueError, TypeError, UnicodeError, KeyError)):
            function(*args, **kwargs)

    def test_actual_unique_guarded_source_produces_only_two_fixed_literals(self):
        self.assertEqual(set(self.source_texts), {('evidence', 0), ('limitations', 0)})
        self.assertEqual(self.source_texts, C.CONFIGURED_IDENTITY_PUBLIC_TEXTS)
        self.assertTrue(all('Bearer ' in text for text in self.source_texts.values()))

    def test_changed_reviewed_source_literal_is_rejected(self):
        changed = self.registry.replace(self.source_texts[('evidence', 0)].encode(), b'Bearer SYNTHETIC_CHANGED_SOURCE')
        self.assertNotEqual(changed, self.registry)
        self.rejects(C.configured_identity_source_texts, changed)

    def test_unguarded_or_incompatible_source_shape_is_rejected(self):
        self.rejects(C.configured_identity_source_texts, self.registry.replace(b'if facts.IdentityConfigured {', b'if true {'))
        self.rejects(C.configured_identity_source_texts, self.registry.replace(b'identityState = StateImplementedLocal', b'identityState = StateBlocked'))

    def test_duplicate_guarded_source_block_is_rejected(self):
        start = self.registry.index(b'\tif facts.IdentityConfigured {')
        end = self.registry.index(b'\n\toperationState', start)
        self.rejects(C.configured_identity_source_texts, self.registry + self.registry[start:end])

    def test_source_encoding_type_and_size_are_bounded(self):
        for raw in (self.registry.decode(), b'\xff', b'', b'x' * ((1 << 20) + 1)):
            self.rejects(C.configured_identity_source_texts, raw)

    def test_git_source_reader_rejects_noncanonical_commit_before_git(self):
        for commit in ('HEAD', 'a' * 39, 'A' * 40, 'a' * 40 + ':other', None):
            with patch.object(C, 'git_file') as git_file:
                self.rejects(C.read_configured_identity_source, ROOT, commit)
                git_file.assert_not_called()

    def test_git_source_reader_uses_supplied_commit_and_fixed_registry_path(self):
        with patch.object(C, 'git_file', return_value=self.registry) as git_file:
            result = C.read_configured_identity_source(ROOT, 'a' * 40)
            git_file.assert_called_once_with(ROOT, 'a' * 40, 'chengwang/internal/capability/registry.go')
            self.assertEqual(result, self.source_texts)
        with patch.object(C, 'git_file', return_value=b'not compatible source'):
            self.rejects(C.read_configured_identity_source, ROOT, 'a' * 40)

    def test_only_complete_configured_identity_documentation_is_allowed(self):
        self.fence()

    def test_default_profile_cannot_use_configured_documentation_exception(self):
        value = copy.deepcopy(LEGACY.report('default'))
        item = by_id(value, 'real_authentication')
        item['evidence'] = [self.source_texts[('evidence', 0)]]
        C.capability(CONTRACT, encoded(value), 'default')
        self.rejects(self.fence, value, profile='default')

    def test_synthetic_token_suffix_cannot_hide_inside_allowed_literal(self):
        for field in ('evidence', 'limitations'):
            value = copy.deepcopy(self.value)
            by_id(value, 'real_authentication')[field][0] += ' SYNTHETIC_SUFFIX_NOT_A_CREDENTIAL'
            C.capability(CONTRACT, encoded(value), 'backend_configured')
            self.rejects(self.fence, value)

    def test_exact_documentation_on_a_different_capability_id_is_rejected(self):
        value = copy.deepcopy(self.value)
        by_id(value, 'durable_operation_control')['evidence'] = [self.source_texts[('evidence', 0)]]
        C.capability(CONTRACT, encoded(value), 'backend_configured')
        self.rejects(self.fence, value)

    def test_exact_documentation_in_wrong_field_or_index_is_rejected(self):
        for destination in (('limitations', 1), ('limitations', 0)):
            value = copy.deepcopy(self.value)
            by_id(value, 'real_authentication')[destination[0]][destination[1]] = self.source_texts[('evidence', 0)]
            C.capability(CONTRACT, encoded(value), 'backend_configured')
            self.rejects(self.fence, value)

    def test_additional_bearer_statement_is_never_implicitly_allowed(self):
        value = copy.deepcopy(self.value)
        by_id(value, 'real_authentication')['limitations'].append('Bearer SYNTHETIC_NOT_A_CREDENTIAL')
        self.rejects(self.fence, value)

    def test_escaped_bearer_outside_the_whitelist_is_scanned_after_decode(self):
        value = copy.deepcopy(self.value)
        by_id(value, 'durable_operation_control')['evidence'] = ['Bearer SYNTHETIC_NOT_A_CREDENTIAL']
        raw = encoded(value).replace(b'Bearer', b'\\u0042earer')
        self.assertNotIn(b'Bearer ', raw)
        self.rejects(C.public_body_fence, CONTRACT, raw, 'CAPABILITIES', 'backend_configured', self.source_texts)

    def test_private_key_marker_is_rejected_for_every_kind_including_assets(self):
        for kind in CONTRACT['captureRules']['kindEnum']:
            self.rejects(C.public_body_fence, CONTRACT, b'PRIVATE KEY SYNTHETIC', kind, 'backend_configured', self.source_texts)

    def test_escaped_private_key_marker_in_capability_text_is_rejected(self):
        value = copy.deepcopy(self.value)
        by_id(value, 'durable_operation_control')['evidence'] = ['PRIVATE KEY SYNTHETIC']
        raw = encoded(value).replace(b'PRIVATE KEY', b'\\u0050RIVATE KEY')
        self.assertNotIn(b'PRIVATE KEY', raw)
        self.rejects(C.public_body_fence, CONTRACT, raw, 'CAPABILITIES', 'backend_configured', self.source_texts)

    def test_other_api_or_document_cannot_borrow_the_static_exception(self):
        for kind in ('SNAPSHOT', 'DOCUMENT'):
            self.rejects(C.public_body_fence, CONTRACT, encoded(self.value), kind, 'backend_configured', self.source_texts)

    def test_existing_asset_static_bearer_exception_is_retained(self):
        C.public_body_fence(CONTRACT, b'/* source literal: Bearer SYNTHETIC */', 'ASSET', 'default')

    def test_full_capability_semantics_run_before_allowing_public_text(self):
        for mutate in (lambda v: v.update(productionControlEnabled=True),
                       lambda v: v['capabilities'].append(copy.deepcopy(v['capabilities'][0]))):
            value = copy.deepcopy(self.value); mutate(value)
            self.rejects(self.fence, value)

    def test_caller_dictionary_cannot_define_a_new_public_whitelist(self):
        for source_texts in ({}, {('other', 0): 'Bearer SYNTHETIC'},
                             {**self.source_texts, ('evidence', 1): 'Bearer SYNTHETIC'},
                             {**self.source_texts, ('evidence', 0): 'Bearer SYNTHETIC'},
                             {('evidence', False): self.source_texts[('evidence', 0)],
                              ('limitations', 0): self.source_texts[('limitations', 0)]}):
            self.rejects(self.fence, source_texts=source_texts)
        self.rejects(C.public_body_fence, CONTRACT, encoded(self.value), 'CAPABILITIES', 'backend_configured', None)

    def test_default_without_markers_keeps_original_semantic_acceptance(self):
        C.public_body_fence(CONTRACT, encoded(LEGACY.report('default')), 'CAPABILITIES', 'default')

    def test_capture_chain_keeps_hash_and_authentication_checks(self):
        rows, files, required, allowed = LEGACY.capture_rows()
        for row in rows:
            if row['kind'] == 'CAPABILITIES':
                raw = encoded(self.value)
                row.update(responseBase64=base64.b64encode(raw).decode(), responseSHA256=C.sha(raw), responseBytes=len(raw))
        C.validate_captures(CONTRACT, rows, files, required, allowed, profile='backend_configured', source_texts=self.source_texts)
        changed = copy.deepcopy(rows); changed[-1]['authorizationPresent'] = True
        self.rejects(C.validate_captures, CONTRACT, changed, files, required, allowed, profile='backend_configured', source_texts=self.source_texts)
        changed = copy.deepcopy(rows); changed[-1]['responseSHA256'] = '0' * 64
        self.rejects(C.validate_captures, CONTRACT, changed, files, required, allowed, profile='backend_configured', source_texts=self.source_texts)


if __name__ == '__main__':
    unittest.main(verbosity=2)
