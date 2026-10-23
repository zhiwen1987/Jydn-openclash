"""Eight frozen pure helper/schema negatives, not a fabricated full PASS.

No browser, server, network, Go, or valid runtime fixture is created. Deliberate
invalid-certificate inputs must fail closed; these cases cannot prove a valid
certificate chain or replace real Linux original-artifact acceptance.
"""
import ast
import base64
import copy
import hashlib
import pathlib
import unittest

import check_matrix as M


def synthetic_inputs():
    ca, leaf = b'NOT_A_CERTIFICATE_AUTHORITY', b'NOT_A_CERTIFICATE_LEAF'
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    pem = lambda raw: '-----BEGIN CERTIFICATE-----\n' + base64.b64encode(raw).decode() + '\n-----END CERTIFICATE-----\n'
    certs = dict(caPEM=pem(ca), leafPEM=pem(leaf))
    driver = dict(normalTrust=dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags='C,,',
        caSHA256=sha(ca), leafSHA256=sha(leaf), homeEnvironmentAbsent=True, legacyDatabaseAbsent=True),
        tls=dict(securityState='secure', protocol='TLS 1.3', cipher='AES_256_GCM', leafSHA256=sha(leaf),
                 caSHA256=sha(ca), serverChainLength=1, leafSignatureVerified=True, ipSANVerified=True),
        certificateChain=[base64.b64encode(leaf).decode()])
    network = [dict(v=1, seq=1, event='START', ordinal=1, requestId='123.1', case='DOCUMENT',
        clock='CDP_MONOTONIC_US', timeUs=1000000, wallTimeUs=1790000000000000)]
    return certs, driver, network


class TestMatrixFullHelpers(unittest.TestCase):
    def reject_tls(self, values):
        with self.assertRaises(ValueError): M.verify_tls(*values)

    def test_01_strict_same_accepts_only_identical_nested_primitive_structures(self):
        value = dict(flag=True, count=0, name='synthetic', values=[None, False, 1, dict(state='closed')])
        self.assertIsNone(M.strict_same(value, copy.deepcopy(value)))

    def test_02_strict_same_rejects_boolean_integer_and_float_aliases_at_every_depth(self):
        for actual, expected in [(True, 1), (1, True), (False, 0), (0, False), (1.0, 1),
                                 ({'exitCode': False}, {'exitCode': 0}),
                                 ({'trust': {'verified': 1}}, {'trust': {'verified': True}}),
                                 ({'limits': [False, 0]}, {'limits': [0, 0]})]:
            with self.assertRaises(ValueError): M.strict_same(actual, expected)

    def test_03_strict_same_rejects_unknown_missing_reordered_and_changed_collections(self):
        for actual, expected in [({'a': 1, 'extra': 2}, {'a': 1}), ({}, {'a': 1}),
                                 ([1, 2], [2, 1]), ([1], [1, 2]), ((1, 2), [1, 2]),
                                 ('1', 1), (None, False)]:
            with self.assertRaises(ValueError): M.strict_same(actual, expected)

    def test_04_tls_rejects_malformed_pem_and_noncertificate_der_even_with_matching_hashes(self):
        self.reject_tls(synthetic_inputs())
        for key in ('caPEM', 'leafPEM'):
            values = synthetic_inputs(); values[0][key] = 'not a certificate'
            self.reject_tls(values)
        values = synthetic_inputs(); values[0]['leafPEM'] = '-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n'
        self.reject_tls(values)

    def test_05_tls_rejects_wrong_leaf_chain_and_untrusted_extra_chain_members(self):
        for chain in [[], [base64.b64encode(b'DIFFERENT_LEAF').decode()],
                      [synthetic_inputs()[1]['certificateChain'][0], base64.b64encode(b'DIFFERENT_CA').decode()],
                      [synthetic_inputs()[1]['certificateChain'][0]] * 3]:
            values = synthetic_inputs(); values[1]['certificateChain'] = chain
            self.reject_tls(values)

    def test_06_tls_declaration_booleans_cannot_be_numeric_success_flags(self):
        for location, key in [('normalTrust', 'homeEnvironmentAbsent'), ('normalTrust', 'legacyDatabaseAbsent'),
                               ('tls', 'leafSignatureVerified'), ('tls', 'ipSANVerified'), ('tls', 'serverChainLength')]:
            values = synthetic_inputs(); values[1][location][key] = 1 if key != 'serverChainLength' else True
            self.reject_tls(values)

    def test_07_tls_rejects_unknown_fields_invalid_cipher_hash_and_document_clock(self):
        changes = [('normalTrust', 'private', 'SYNTHETIC_ONLY'), ('tls', 'private', 'SYNTHETIC_ONLY'),
                   ('tls', 'cipher', {'unbounded': 'SYNTHETIC_ONLY'}), ('tls', 'leafSHA256', '0' * 64),
                   ('tls', 'securityState', 'insecure'), ('tls', 'protocol', 'TLS 1.0')]
        for location, key, value in changes:
            values = synthetic_inputs(); values[1][location][key] = value
            self.reject_tls(values)
        for clock in (True, -1, 9007199254740992):
            values = synthetic_inputs(); values[2][0]['wallTimeUs'] = clock
            self.reject_tls(values)

    def test_08_full_verifier_calls_strict_schema_and_offline_tls_helpers_directly(self):
        tree = ast.parse(pathlib.Path(M.__file__).read_bytes())
        verify = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'verify')
        calls = {n.func.id for n in ast.walk(verify) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertIn('strict_same', calls); self.assertIn('verify_tls', calls)
        tls = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'verify_tls')
        literals = [n.value for n in ast.walk(tls) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        # Official OpenSSL verification-options documents that -trusted itself
        # implies no-CAfile/no-CApath/no-CAstore; do not require redundant flags.
        for option in ('verify', '-verify_ip', '127.0.0.1', '-attime', '-trusted', '-check_ss_sig', '-purpose', 'sslserver'):
            self.assertIn(option, literals)


FROZEN_NAMES = tuple(unittest.defaultTestLoader.getTestCaseNames(TestMatrixFullHelpers))
FROZEN_NAMES_SHA256 = '2cff899bb14b0df8a53949c8a4ea7deded555f144e1317f898a380c2d39b7902'
FROZEN_FULL_NAMES_SHA256 = 'f19a2b552b0b203536312c827dd7e7fef0fc24b7ccb20902fed5403818f40043'
assert len(FROZEN_NAMES) == len(set(FROZEN_NAMES)) == 8
assert hashlib.sha256('\n'.join(sorted(FROZEN_NAMES)).encode()).hexdigest() == FROZEN_NAMES_SHA256
assert hashlib.sha256('\n'.join('test_check_matrix_full.TestMatrixFullHelpers.' + name for name in sorted(FROZEN_NAMES)).encode()).hexdigest() == FROZEN_FULL_NAMES_SHA256

if __name__ == '__main__':
    unittest.main(verbosity=2)
