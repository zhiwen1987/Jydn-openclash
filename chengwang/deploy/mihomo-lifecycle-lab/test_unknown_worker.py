"""SYNTHETIC pure-byte disclosure models; no worker/main/Go/OS execution.

Invented credentials and reports test export refusal, not controller responses,
UNKNOWN lifecycle semantics, actual private witnesses or production behavior.
"""
import base64
import copy
import json
from pathlib import Path
import unittest

import unknown_worker as W

COMMIT = 'a'*40


class SyntheticUnknownDisclosureModels(unittest.TestCase):
    def model(self, request=b'{}', response=b'{}'):
        encode = lambda raw: base64.b64encode(raw).decode('ascii')
        return dict(http=[dict(requestBody=encode(request), responseBody=encode(response))])

    def full(self):
        value = dict.fromkeys(W.REPORT_KEYS)
        value.update(schema='chengwang.mihomo-unknown-http-experiment/v1', scope=W.SCOPE,
                     sourceCommit=COMMIT, outcome='FAIL', failureCode='SYNTHETIC_NOT_EXECUTED',
                     http=[], production=False, fullPayloadProven=False, internetBusinessProven=False)
        return value

    def headers(self, raw=b'application/json'):
        return dict(records=[dict(headers=dict(contentTypeValuesB64=[base64.b64encode(raw).decode('ascii')],
                     contentEncodingValuesB64=[], transferEncodingValuesB64=[]))])

    def fenced(self, report, forbidden):
        for raw in W.report_decoded_bodies(report):
            W.disclosure(raw, forbidden)

    def test_unaligned_actual_request_body_secret_is_rejected(self):
        secret = b'synthetic-private-request-token'
        report = self.model(request=b'{"xx":"'+secret+b'"}')
        self.assertNotIn(base64.b64encode(secret), report['http'][0]['requestBody'].encode('ascii'))
        with self.assertRaises(ValueError):
            self.fenced(report, {secret})

    def test_unaligned_actual_response_body_secret_is_rejected(self):
        secret = b'synthetic-private-response-token'
        with self.assertRaises(ValueError):
            self.fenced(self.model(response=b'[{"xx":"'+secret+b'"}]'), {secret})

    def test_dropped_legacy_body_is_rejected_instead_of_fabricated(self):
        report = self.model()
        report['dropped'] = dict(generatedBody='e30=')
        with self.assertRaises(ValueError):
            W.report_decoded_bodies(report)

    def test_legacy_normal_service_report_cannot_be_renamed(self):
        value = self.full()
        value['schema'] = 'chengwang.mihomo-service-http-experiment/v1'
        with self.assertRaises(ValueError):
            W.validate_report(value, COMMIT)

    def test_null_transport_body_is_inspected_without_replacing_original(self):
        report = self.model(request=b'', response=b'')
        report['http'][0]['requestBody'] = None
        original = copy.deepcopy(report)
        self.assertEqual(W.report_decoded_bodies(report), [b'', b''])
        self.assertEqual(report, original)

    def test_canonical_base64_keeps_binary_and_boundary_bytes(self):
        for raw in (b'\x00\xff\xfe', b'a', b'ab', b'abc', b'x'*(16 << 10)):
            self.assertEqual(W.encoded_body(base64.b64encode(raw).decode('ascii'), 16 << 10), raw)

    def test_noncanonical_base64_and_whitespace_are_rejected(self):
        for value in ('YQ==\n', 'YQ', 'YR==', 'YQ===', 'YWJ=', '!!!!', '-_=='):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                W.encoded_body(value, 16 << 10)

    def test_decoded_body_budget_cannot_be_hidden_by_encoding(self):
        raw = b'x'*((16 << 10)+1)
        with self.assertRaises(ValueError):
            W.encoded_body(base64.b64encode(raw).decode('ascii'), 16 << 10)

    def test_nonstring_base64_does_not_accept_boolean_or_number(self):
        for value in (False, True, 0, 1, [], {}):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                W.encoded_body(value, 16 << 10)

    def test_missing_http_body_is_not_assumed_empty(self):
        report = self.model()
        del report['http'][0]['responseBody']
        with self.assertRaises(ValueError):
            W.report_decoded_bodies(report)

    def test_http_row_types_and_count_are_bounded(self):
        for value in (None, {}, [None], self.model()['http']*33):
            report = self.model()
            report['http'] = value
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                W.report_decoded_bodies(report)

    def test_unaligned_selected_header_secret_is_rejected_after_decode(self):
        secret = b'synthetic-header-private-value'
        transcript = self.headers(b'application/json;model="'+secret+b'"')
        with self.assertRaises(ValueError):
            for value in W.decoded_header_values(transcript):
                W.disclosure(value, {secret})

    def test_missing_or_aliased_selected_header_arrays_are_rejected(self):
        for value in (None, '', False, {}, 'e30='):
            changed = self.headers()
            changed['records'][0]['headers']['contentEncodingValuesB64'] = value
            with self.assertRaises(ValueError):
                W.decoded_header_values(changed)
        changed = self.headers()
        del changed['records'][0]['headers']['transferEncodingValuesB64']
        with self.assertRaises(ValueError):
            W.decoded_header_values(changed)
        for value in (None, False, 0, {}, []):
            changed = self.headers()
            changed['records'][0]['headers']['contentEncodingValuesB64'] = [value]
            with self.assertRaises(ValueError):
                W.decoded_header_values(changed)

    def test_selected_headers_have_record_value_and_byte_limits(self):
        variants = []
        value = self.headers(); value['records'] *= 9; variants.append(value)
        value = self.headers(); value['records'][0]['headers']['contentTypeValuesB64'] *= 17; variants.append(value)
        variants.append(self.headers(b'x'*((16 << 10)+1)))
        for value in variants:
            with self.assertRaises(ValueError):
                W.decoded_header_values(value)

    def test_actual_full_yaml_variants_participate_in_fence(self):
        raw = b'mixed-port: 28411\nsecret: SYNTHETIC_PRIVATE_CONTROLLER\n'
        key = b'-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END PRIVATE KEY-----\n'
        forbidden = W.private_variants(['synthetic-controller'], [raw, b'synthetic-candidate-yaml'], key)
        for value in (raw, base64.b64encode(raw), raw.hex().upper().encode('ascii'), json.dumps(raw.decode()).encode('ascii')):
            with self.assertRaises(ValueError):
                W.disclosure(value, forbidden)

    def test_all_seven_http_credentials_and_controller_route_markers_are_fenced(self):
        values = ['synthetic-'+role+'-private-token' for role in ('viewer', 'operator', 'approver', 'auditor', 'admin', 'foreign', 'wrong-scope')]
        values += ['synthetic-controller', 'synthetic-route-a', 'synthetic-route-b']
        key = b'-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----\n'
        forbidden = W.private_variants(values, [b'synthetic-base-yaml', b'synthetic-candidate-yaml'], key)
        for token in values:
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.fenced(self.model(response=b'{"x":"'+token.encode('ascii')+b'"}'), forbidden)

    def test_private_tls_key_and_encoded_forms_never_leave_fence(self):
        key = b'-----BEGIN PRIVATE KEY-----\nSYNTHETIC-ONLY-NOT-A-KEY\n-----END PRIVATE KEY-----\n'
        forbidden = W.private_variants(['synthetic-token'], [b'synthetic-yaml'], key)
        for raw in (key, base64.b64encode(key), key.hex().upper().encode('ascii'), b'-----BEGIN OPENSSH PRIVATE KEY-----\nX'):
            with self.assertRaises(ValueError):
                W.disclosure(raw, forbidden)

    def test_missing_tls_private_witness_cannot_use_public_certificate(self):
        for key in (None, b'', b'-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----', b'-----BEGIN PRIVATE KEY-----\nX'):
            with self.assertRaises(ValueError):
                W.private_variants(['synthetic-token'], [b'synthetic-yaml'], key)

    def test_failed_disclosure_preserves_original_bytes(self):
        raw = b'{"x":"synthetic-secret"}\n'
        original = bytes(raw)
        with self.assertRaises(ValueError):
            W.disclosure(raw, {b'synthetic-secret'})
        self.assertEqual(raw, original)

    def test_nonsecret_original_remains_byte_exact(self):
        raw = b'{"code":"mihomo_lab_ok", "state":"UNKNOWN"}\n'
        report = self.model(response=raw)
        self.assertIsNone(W.disclosure(raw, {b'not-present-synthetic-secret'}))
        self.assertEqual(W.report_decoded_bodies(report)[1], raw)

    def test_report_wrong_commit_scope_or_proof_alias_is_rejected(self):
        for key, replacement in (('sourceCommit', 'b'*40), ('scope', 'legacy-normal'),
                                  ('production', 0), ('fullPayloadProven', True),
                                  ('internetBusinessProven', 0), ('controllerReceivedCount', 1), ('outcome', True)):
            report = self.full(); report[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                W.validate_report(report, COMMIT)

    def test_report_extra_missing_or_dropped_fields_cannot_export_as_unknown(self):
        for kind in ('extra', 'missing', 'dropped'):
            report = self.full()
            if kind == 'missing': del report['fault']
            else: report['dropped' if kind == 'dropped' else 'inventedPass'] = None
            with self.assertRaises(ValueError):
                W.validate_report(report, COMMIT)

    def test_unobserved_runtime_is_null_not_inferred_from_go_exit(self):
        for report in ({}, {'before': None}, {'before': {}}, {'before': {'observedProcessMatchesHead': 1}}):
            self.assertIsNone(W.actual_observed(report))

    def test_only_actual_before_boolean_becomes_execution_observation(self):
        self.assertIs(W.actual_observed({'before': {'observedProcessMatchesHead': True}}), True)
        self.assertIs(W.actual_observed({'before': {'observedProcessMatchesHead': False}}), False)

    def test_go_arguments_are_serial_dual_package_and_dual_tag(self):
        args = W.go_arguments({'goTimeoutSeconds': 75}, '/SYNTHETIC/readonly-go')
        self.assertEqual(args, ['/SYNTHETIC/readonly-go/bin/go', 'test', '-json', '-count=1', '-shuffle=off', '-p=1',
            '-tags=chengwang_mihomo_service,chengwang_mihomo_faults',
            '-run=^(TestLabReloadFaultCapsuleModelBoundaries|TestMihomoServiceHTTPUnknownOutcomeBlocksReplayAndNewPlan)$',
            '-timeout=75s', './internal/adapter/mihomo', './internal/serverruntime'])

    def test_source_contract_rejects_timeout_tag_package_or_boolean_drift(self):
        value = json.loads(Path(W.__file__).with_name('unknown_contract.json').read_bytes())
        self.assertEqual(W.validate_contract(value), value)
        for key, replacement in (('tags', ['chengwang_mihomo_service']), ('goPackages', ['./internal/serverruntime']),
                                 ('topTests', list(reversed(W.TOPS))), ('goTimeoutSeconds', 90),
                                 ('outerGoTimeoutSeconds', 91), ('production', 0)):
            changed = copy.deepcopy(value); changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                W.validate_contract(changed)

    def test_exact_public_mapping_has_unknown_originals_and_no_legacy_acceptance(self):
        self.assertEqual(len(W.PUBLIC), 58)
        self.assertEqual(len(set(W.PUBLIC)), 58)
        self.assertEqual(len(W.MAPPING), 47)
        self.assertEqual(W.MAPPING['unknown-report.json'], 'unknown-report.private.json')
        self.assertIn('unknown.json', W.PUBLIC)
        self.assertIn('unknown.stderr', W.PUBLIC)
        for name in ('e2e-report.json', 'service.json', 'service.stderr', 'dropped-response.json'):
            self.assertNotIn(name, W.PUBLIC)

    def test_execution_keeps_real_nullable_state_without_fabricating_exit(self):
        value = W.execution(dict(commit=COMMIT, formatExit=None, goExit=None, observed=None))
        self.assertEqual(value['schema'], 'chengwang.mihomo-unknown-execution/v1')
        self.assertIsNone(value['formatExit'])
        self.assertIsNone(value['goExit'])
        self.assertIsNone(value['realMihomoExecutionObserved'])
        self.assertIs(value['production'], False)


if __name__ == '__main__':
    unittest.main()
