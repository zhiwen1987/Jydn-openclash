"""CPU-only SYNTHETIC disclosure-fence models; never invoke worker/main/OS.

These invented tokens/HTTP bodies prove specific fence behavior, not actual
private production bytes, Linux custody, Go execution or service availability.
"""
import base64
import copy
import unittest

import service_worker as W


class SyntheticServiceDisclosureModels(unittest.TestCase):
    def model(self, request=b'{}', response=b'{}', dropped=b'{}'):
        encode = lambda raw: base64.b64encode(raw).decode('ascii')
        return dict(http=[dict(requestBody=encode(request), responseBody=encode(response))],
                    dropped=dict(generatedBody=encode(dropped)))

    def fenced(self, report, forbidden):
        for raw in W.report_decoded_bodies(report):
            W.disclosure(raw, forbidden)

    def test_unaligned_request_secret_is_not_hidden_by_outer_base64(self):
        secret = b'private-model-token-with-distinct-alignment'
        raw = b'{"xx":"'+secret+b'"}'
        report = self.model(request=raw)
        outer = report['http'][0]['requestBody'].encode('ascii')
        self.assertNotIn(secret, outer)
        self.assertNotIn(base64.b64encode(secret), outer)
        with self.assertRaises(ValueError):
            self.fenced(report, {secret})

    def test_exact_source_owned_format_membership(self):
        self.assertEqual(W.FMT, (
            'internal/adapter/mihomo/write_client.go',
            'internal/mihomodeploy/lab_service_acceptance_linux.go',
            'internal/serverruntime/mihomo_lab_runtime.go',
            'internal/serverruntime/mihomo_lab_config_test.go',
            'internal/serverruntime/mihomo_service_e2e_linux_test.go',
            'internal/authn/store.go',
            'internal/serverruntime/runtime.go',
            'internal/serverruntime/mihomo_continuous_recovery_hook_default.go'))

    def test_unaligned_response_secret_is_rejected_after_decoding(self):
        secret = b'response-private-model-value'
        with self.assertRaises(ValueError):
            self.fenced(self.model(response=b'[{"x":"'+secret+b'"}]'), {secret})

    def test_generated_unobserved_response_participates_in_fence(self):
        secret = b'private-generated-response-value'
        with self.assertRaises(ValueError):
            self.fenced(self.model(dropped=b'XX'+secret+b'YY'), {secret})

    def test_null_and_empty_transport_bodies_remain_distinct_inputs(self):
        report = self.model(request=b'', response=b'')
        report['dropped']['generatedBody'] = None
        self.assertEqual(W.report_decoded_bodies(report), [b'', b'', b''])

    def test_canonical_base64_round_trip_keeps_original_bytes(self):
        for raw in (b'\x00\xff\xfe', b'a', b'ab', b'abc', b'x'*(16 << 10)):
            self.assertEqual(W.encoded_body(base64.b64encode(raw).decode('ascii'), 16 << 10), raw)

    def test_base64_whitespace_bad_padding_and_noncanonical_pad_bits_rejected(self):
        for value in ('YQ==\n', 'YQ', 'YR==', 'YQ===', 'YWJ=', '!!!!', '-_=='):
            with self.subTest(value=value):
                with self.assertRaises((ValueError, TypeError)):
                    W.encoded_body(value, 16 << 10)

    def test_encoded_body_limit_is_applied_to_decoded_bytes(self):
        raw = b'x'*((16 << 10)+1)
        with self.assertRaises(ValueError):
            W.encoded_body(base64.b64encode(raw).decode('ascii'), 16 << 10)

    def test_nonstring_encoded_body_cannot_use_numeric_or_boolean_alias(self):
        for value in (False, True, 0, 1, [], {}):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    W.encoded_body(value, 16 << 10)

    def test_missing_http_body_cannot_be_silently_treated_as_absent(self):
        report = self.model()
        del report['http'][0]['responseBody']
        with self.assertRaises(KeyError):
            W.report_decoded_bodies(report)

    def test_http_rows_and_dropped_report_have_bounded_closed_types(self):
        base = self.model()
        variants = []
        for key, value in (('http', None), ('http', {}), ('http', [None]),
                           ('http', base['http']*33), ('dropped', []), ('dropped', None)):
            changed = copy.deepcopy(base)
            changed[key] = value
            variants.append(changed)
        for changed in variants:
            with self.assertRaises(ValueError):
                W.report_decoded_bodies(changed)

    def test_each_private_marker_is_rejected_without_rewriting_public_original(self):
        markers = {b'controller-model-secret', b'route-a-model-secret', b'http-model-token'}
        raw = b'{"body":"route-a-model-secret"}'
        before = bytes(raw)
        with self.assertRaises(ValueError):
            W.disclosure(raw, markers)
        self.assertEqual(raw, before)

    def test_nonsecret_original_is_kept_byte_exact(self):
        raw = b'{"code":"mihomo_lab_ok", "proof":{"production":false}}\n'
        self.assertIsNone(W.disclosure(raw, {b'not-present-model-secret'}))
        self.assertEqual(W.report_decoded_bodies(self.model(response=raw))[1], raw)

    def test_private_tls_key_original_and_encoded_forms_are_fenced(self):
        key = b'-----BEGIN PRIVATE KEY-----\nMODEL-ONLY-NOT-A-KEY\n-----END PRIVATE KEY-----\n'
        forbidden = W.private_variants(['model-controller-value'], [b'model-config-bytes'], key)
        for original in (key, base64.b64encode(key), key.hex().upper().encode('ascii'),
                         b'-----BEGIN OPENSSH PRIVATE KEY-----\nMODEL\n'):
            with self.subTest(original=original[:20]):
                with self.assertRaises(ValueError):
                    W.disclosure(original, forbidden)
        with self.assertRaises(ValueError):
            self.fenced(self.model(dropped=b'{"key":"-----BEGIN PRIVATE KEY-----"}'), forbidden)

    def test_missing_private_key_fence_cannot_be_substituted_by_public_certificate(self):
        for key in (b'', b'-----BEGIN CERTIFICATE-----\nMODEL\n-----END CERTIFICATE-----',
                    b'-----BEGIN PRIVATE KEY-----\nMODEL', None):
            with self.assertRaises(ValueError):
                W.private_variants(['model-token'], [b'model-config'], key)


if __name__ == '__main__':
    unittest.main()
