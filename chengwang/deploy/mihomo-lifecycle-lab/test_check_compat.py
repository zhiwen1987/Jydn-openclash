"""Synthetic protocol models only. Never execute Go, Mihomo, a service or namespace."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import check_compat as C

COMMIT = '1' * 40


def wire(value): return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
def hashed(raw): return hashlib.sha256(raw).hexdigest()


def fixture():
    """All process/kernel identities below are explicitly invented model data."""
    sources = {p: b'SYNTHETIC_SOURCE_NOT_ACTUAL_KERNEL_OR_GIT\n' for p in C.FILES}
    sources[C.PREFIX + 'compat_contract.json'] = (Path(__file__).parent / 'compat_contract.json').read_bytes()
    sources['chengwang/internal/mihomodeploy/runtime_compat_linux_test.go'] = (
        '//go:build linux && chengwang_mihomo_compat\npackage mihomodeploy\n'
        + '\n'.join('func ' + name + '(t *testing.T) { }' for name in C.TOP)
        + '\n// Synthetic subtest labels only: "base" "candidate"\n').encode()
    sources[C.CANDIDATE + 'pin.json'] = (Path(__file__).parents[2] / 'tools/mihomo-runtime-candidate/pin.json').read_bytes()
    source = dict(projectSourceCommit=COMMIT, sourceFiles=[dict(path=p, bytes=len(sources[p]), sha256=hashed(sources[p])) for p in C.CONSUMER_FILES], pinSHA256=hashed(sources[C.CANDIDATE + 'pin.json']))
    elf = dict(bytes=12345, sha256='a' * 64, byteOrder='little', elfClass='ELF64', machine='AMD64', type='EXEC', entryPoint=4194304,
        programHeaderCount=5, loadSegments=3, sectionHeaderCount=12, executableEntryMapped=True)
    receipt = wire(dict(schema='chengwang.mihomo-candidate-consumption/v1', state='PINNED_GZIP_EXPANDED_NOT_EXECUTED', source=source,
        component='MetaCubeX/mihomo', version='v1.19.32', upstreamSourceCommit=C.UPSTREAM,
        archive=dict(name=C.ASSET, bytes=7890, sha256=C.PUBLISHED, pinBasis='PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL'),
        gzip=dict(singleMember=True, complete=True, trailerCRC32='1234abcd', trailerISIZE=elf['bytes']), elf=elf,
        output=dict(path='mihomo', mode='0500', receiptMode='0400', directoryMode='0700'), runtimeExecuted=False, runtimeCompatibilityProven=False,
        businessAvailabilityProven=False, publisherSignatureProven=False, productionApproved=False, production=False))
    host = dict(networkNamespace='net:[1]', mountNamespace='mnt:[2]', pidNamespace='pid:[3]', resolvSHA256='b' * 64)
    custody = dict(elf=dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', uid=1001, gid=1001),
        receipt=dict(sha256=hashed(receipt), bytes=len(receipt), mode='0400', uid=1001, gid=1001))
    sandbox = dict(schema='chengwang.mihomo-compat-sandbox/v1', sourceCommit=COMMIT, uid=10001, gid=10001,
        effectiveCaps='0000000000000000', noNewPrivileges=True, networkNamespace='net:[4]', mountNamespace='mnt:[5]', pidNamespace='pid:[6]',
        environmentKeys=C.ENV, interfaceNames=['lo'], defaultV4Routes=[], defaultV6Routes=[], sourceModuleSHA256=hashed(sources['chengwang/go.mod']),
        sourceReadOnly=True, goReadOnly=True, kernelCopy=dict(sha256=elf['sha256'], bytes=elf['bytes'], mode='0500', readOnly=True, executable=True),
        inputCustody=dict(before=copy.deepcopy(custody), after=copy.deepcopy(custody)))
    raw = {p: b'' for p in C.PUBLIC}
    raw.update({'consumption.json':receipt, 'consumption-independent.json':receipt, 'host-before.json':wire(host), 'host-after.json':wire(host),
        'sandbox.json':wire(sandbox), 'go-version.txt':b'go version go1.23.12 linux/amd64\n',
        'execution.json':wire(dict(schema='chengwang.mihomo-compat-execution/v1', sourceCommit=COMMIT, formatExit=0, goExit=0, realMihomoExecutionObserved=True, production=False))})
    package = 'chengwang/internal/mihomodeploy'
    events = [dict(Action='start', Package=package)]
    for name in C.TOP:
        events.append(dict(Action='run', Package=package, Test=name))
        if name == 'TestMihomoCompatGeneratedConfigs':
            for sub in C.SUB: events.extend([dict(Action='run', Package=package, Test=sub), dict(Action='pass', Package=package, Test=sub)])
        events.append(dict(Action='pass', Package=package, Test=name))
    events.append(dict(Action='pass', Package=package))
    raw['compat.json'] = b''.join(wire(e) for e in events)
    timestamp = 'time="2026-10-24T12:00:00.123456789Z" '
    for index, case in enumerate(C.CASES):
        if case == 'version': out = b'Mihomo Meta v1.19.32 linux amd64 with go1.25.3 2026-10-20T12:00:00Z\nUse tags: with_gvisor\n'
        elif case == 'malformed': out = (timestamp + 'level=error msg="yaml: line 1: did not find expected node content"\nconfiguration test failed\n').encode()
        else:
            messages = ['Start initial configuration in progress', 'Geodata Loader mode: memconservative',
                'Geosite Matcher implementation: succinct', 'Initial configuration complete, total time: 1ms']
            out = (''.join(timestamp + 'level=info msg="' + message + '"\n' for message in messages)
                + 'configuration file config.yaml test is successful\n').encode()
        stdin = b'' if case == 'version' else C.MALFORMED if case == 'malformed' else ('SYNTHETIC_PRIVATE_CONFIG_' + case).encode()
        stdio = lambda data:dict(bytes=len(data), sha256=hashed(data), totalBytes=len(data), truncated=False)
        record = dict(schema='chengwang.mihomo-compat-exec/v1', sourceCommit=COMMIT, case=case, binarySHA256=elf['sha256'], binaryBytes=elf['bytes'],
            consumptionSHA256=hashed(receipt), argvClass='VERSION' if case == 'version' else 'STDIN_TEST', inputSHA256=None if case == 'version' else hashed(stdin), inputBytes=len(stdin),
            started=True, pid=100 + index, procStartTicks=None, procObservationState='NOT_OBSERVED', waitReturned=True,
            waitErrorClass='EXIT_STATUS' if case == 'malformed' else 'NONE', exitCode=1 if case == 'malformed' else 0, signal=None,
            timedOut=False, killSent=False, processGroupAbsent=True, stdout=stdio(out), stderr=stdio(b''))
        raw[case + '.exec.json'] = wire(record); raw[case + '.stdout'] = out
    return raw, sources


class SyntheticCompatEvidenceModels(unittest.TestCase):
    def reject_json(self, filename, change):
        raw, sources = fixture(); value = json.loads(raw[filename]); change(value); raw[filename] = wire(value)
        with self.assertRaises((ValueError, KeyError, TypeError, UnicodeError)): C.verify_raw(raw, sources, COMMIT)

    def test_synthetic_complete_protocol_model_is_not_actual_kernel_execution(self):
        raw, sources = fixture(); report = C.verify_raw(raw, sources, COMMIT)
        self.assertEqual(report['tests'], dict(topLevel=3, subtests=2, passingSemanticTests=5, skips=0))
        self.assertFalse(report['production']); self.assertEqual(report['scope'], C.SCOPE)

    def test_missing_or_private_extra_public_file_rejects(self):
        for remove in (False, True):
            raw, sources = fixture()
            if remove: del raw['candidate.stderr']
            else: raw['base.config.private.yaml'] = b'PRIVATE'
            with self.assertRaises(ValueError): C.verify_raw(raw, sources, COMMIT)

    def test_nonempty_formatter_or_go_stderr_rejects(self):
        for filename in ('compat.stderr', 'gofmt.patch', 'gofmt.stderr'):
            raw, sources = fixture(); raw[filename] = b'original failure\n'
            with self.assertRaises(ValueError): C.verify_raw(raw, sources, COMMIT)

    def test_false_execution_or_nonzero_wrapper_exit_rejects(self):
        for key, value in [('formatExit', 1), ('goExit', 1), ('goExit', False), ('realMihomoExecutionObserved', False), ('production', True)]:
            self.reject_json('execution.json', lambda d:d.__setitem__(key, value))

    def test_wrong_go_version_rejects(self):
        raw, sources = fixture(); raw['go-version.txt'] = b'go version go1.24.0 linux/amd64\n'
        with self.assertRaises(ValueError): C.verify_raw(raw, sources, COMMIT)

    def test_consumption_original_and_independent_must_be_byte_equal(self):
        raw, sources = fixture(); raw['consumption-independent.json'] += b' '
        with self.assertRaises(ValueError): C.verify_raw(raw, sources, COMMIT)

    def test_receipt_does_not_mutate_historical_execution_or_signature_status(self):
        for key in ('runtimeExecuted', 'publisherSignatureProven', 'productionApproved', 'businessAvailabilityProven'):
            raw, sources = fixture(); receipt=json.loads(raw['consumption.json']);receipt[key]=True
            raw['consumption.json']=raw['consumption-independent.json']=wire(receipt)
            with self.assertRaises(ValueError): C.verify_raw(raw, sources, COMMIT)

    def test_wrong_asset_or_source_binding_rejects(self):
        for kind in ('asset', 'source'):
            raw,sources=fixture(); receipt=json.loads(raw['consumption.json'])
            if kind=='asset': receipt['archive']['sha256']='c'*64
            else: receipt['source']['sourceFiles'][0]['sha256']='c'*64
            raw['consumption.json']=raw['consumption-independent.json']=wire(receipt)
            with self.assertRaises(ValueError): C.verify_raw(raw,sources,COMMIT)

    def test_kernel_copy_identity_and_permissions_reject(self):
        for key,value in [('sha256','c'*64),('bytes',1),('mode','0700'),('readOnly',False),('executable',False),('readOnly',1),('executable',1)]:
            self.reject_json('sandbox.json',lambda d:d['kernelCopy'].__setitem__(key,value))

    def test_changed_original_input_custody_rejects(self):
        self.reject_json('sandbox.json',lambda d:d['inputCustody']['after']['elf'].__setitem__('sha256','c'*64))

    def test_all_consumption_source_file_sizes_reject_equal_float_and_boolean_types(self):
        raw,sources=fixture()
        for index in range(len(C.CONSUMER_FILES)):
            original=json.loads(raw['consumption.json'])['source']['sourceFiles'][index]['bytes']
            for number in (float(original),True,False):
                receipt=json.loads(raw['consumption.json']);receipt['source']['sourceFiles'][index]['bytes']=number
                with self.assertRaises(ValueError):C.consumption(wire(receipt),sources,COMMIT)

    def test_all_after_custody_numeric_fields_reject_equal_float_and_boolean_types(self):
        raw,sources=fixture();elf=C.consumption(raw['consumption.json'],sources,COMMIT)
        for name in ('elf','receipt'):
            for field in ('bytes','uid','gid'):
                original=json.loads(raw['sandbox.json'])['inputCustody']['before'][name][field]
                for number in (float(original),True,False):
                    value=json.loads(raw['sandbox.json'])
                    # Valid numeric UID/GID0/1 makes bool False/True compare
                    # equal under Python==, isolating the after-side type gate.
                    if type(number) is bool and field in ('uid','gid'):
                        value['inputCustody']['before'][name][field]=int(number)
                    value['inputCustody']['after'][name][field]=number
                    with self.assertRaises(ValueError):C.sandbox(wire(value),raw['host-before.json'],raw['host-after.json'],sources,COMMIT,elf,raw['consumption.json'])

    def test_source_or_go_writable_rejects(self):
        for key in ('sourceReadOnly','goReadOnly'):self.reject_json('sandbox.json',lambda d:d.__setitem__(key,False))

    def test_network_egress_interface_or_routes_reject(self):
        for key,value in [('interfaceNames',['lo','eth0']),('defaultV4Routes',['default']),('defaultV6Routes',['::/0'])]:
            self.reject_json('sandbox.json',lambda d:d.__setitem__(key,value))

    def test_root_caps_or_missing_nnp_rejects(self):
        for key,value in [('uid',0),('gid',0),('effectiveCaps','0000000000000001'),('noNewPrivileges',False)]:
            self.reject_json('sandbox.json',lambda d:d.__setitem__(key,value))

    def test_environment_extra_or_missing_rejects(self):
        for change in (lambda d:d['environmentKeys'].append('HTTP_PROXY'),lambda d:d['environmentKeys'].remove('TMPDIR')):
            self.reject_json('sandbox.json',change)

    def test_host_change_or_shared_namespace_rejects(self):
        self.reject_json('host-after.json',lambda d:d.__setitem__('resolvSHA256','c'*64))
        self.reject_json('sandbox.json',lambda d:d.__setitem__('networkNamespace','net:[1]'))

    def test_started_pid_wait_and_group_absence_are_mandatory(self):
        for key,value in [('started',False),('pid',None),('pid',True),('waitReturned',False),('processGroupAbsent',None)]:
            self.reject_json('base.exec.json',lambda d:d.__setitem__(key,value))

    def test_observed_proc_requires_real_positive_ticks_and_unobserved_requires_null(self):
        self.reject_json('base.exec.json',lambda d:d.__setitem__('procStartTicks',0))
        self.reject_json('base.exec.json',lambda d:d.__setitem__('procObservationState','OBSERVED'))
        raw,sources=fixture();v=json.loads(raw['base.exec.json']);v.update(procStartTicks=12345,procObservationState='OBSERVED');raw['base.exec.json']=wire(v)
        C.verify_raw(raw,sources,COMMIT)

    def test_wrong_exec_role_binary_or_receipt_binding_rejects(self):
        for key,value in [('case','candidate'),('sourceCommit','2'*40),('binarySHA256','c'*64),('consumptionSHA256','c'*64),('argvClass','VERSION')]:
            self.reject_json('base.exec.json',lambda d:d.__setitem__(key,value))

    def test_malformed_requires_normal_exit_status_not_timeout_signal_or_wait_error(self):
        for key,value in [('exitCode',0),('waitErrorClass','WAIT_ERROR'),('signal','SIGKILL'),('timedOut',True),('killSent',True)]:
            self.reject_json('malformed.exec.json',lambda d:d.__setitem__(key,value))

    def test_valid_case_nonzero_and_malformed_stdin_substitution_rejects(self):
        self.reject_json('candidate.exec.json',lambda d:d.__setitem__('exitCode',1))
        self.reject_json('malformed.exec.json',lambda d:d.__setitem__('inputSHA256','c'*64))

    def test_version_absent_stdin_is_null_and_never_invented_empty_hash(self):
        self.reject_json('version.exec.json',lambda d:d.__setitem__('inputSHA256',hashed(b'')))
        self.reject_json('version.exec.json',lambda d:d.__setitem__('inputBytes',1))

    def test_real_worker_is_mandatory_source_and_publisher_pin_cannot_gain_approval(self):
        self.assertEqual(len(C.FILES),93); self.assertIn(C.PREFIX+'compat_worker.py',C.FILES)
        raw,sources=fixture();pin=json.loads(sources[C.CANDIDATE+'pin.json']);pin['productionApproved']=True;sources[C.CANDIDATE+'pin.json']=wire(pin)
        receipt=json.loads(raw['consumption.json']);receipt['source']['pinSHA256']=hashed(sources[C.CANDIDATE+'pin.json'])
        receipt['source']['sourceFiles'][0].update(bytes=len(sources[C.CANDIDATE+'pin.json']),sha256=hashed(sources[C.CANDIDATE+'pin.json']))
        raw['consumption.json']=raw['consumption-independent.json']=wire(receipt)
        with self.assertRaises(ValueError):C.verify_raw(raw,sources,COMMIT)

    def test_process_ids_and_config_inputs_cannot_be_collapsed(self):
        self.reject_json('candidate.exec.json',lambda d:d.__setitem__('pid',101))
        raw,sources=fixture();a=json.loads(raw['base.exec.json']);b=json.loads(raw['candidate.exec.json']);b['inputSHA256']=a['inputSHA256'];raw['candidate.exec.json']=wire(b)
        with self.assertRaises(ValueError):C.verify_raw(raw,sources,COMMIT)

    def test_original_stdio_hash_size_total_and_truncation_all_recomputed(self):
        for key,value in [('sha256','c'*64),('bytes',0),('totalBytes',65537),('truncated',True)]:
            self.reject_json('base.exec.json',lambda d:d['stdout'].__setitem__(key,value))

    def test_private_or_unrecognized_original_stdio_rejects_even_after_rehash(self):
        for data in (b'secret: PRIVATE\n',b'https://127.0.0.1/private\n',b'a'*64+b'\n',b'c2VjcmV0OiBQUklWQVRF\n',b'\x1b[31mhidden\n',b'\xff\n'):
            raw,sources=fixture();v=json.loads(raw['base.exec.json']);raw['base.stdout']=data;v['stdout'].update(bytes=len(data),totalBytes=len(data),sha256=hashed(data));raw['base.exec.json']=wire(v)
            with self.assertRaises((ValueError,UnicodeError)):C.verify_raw(raw,sources,COMMIT)

    def test_version_and_success_path_are_pinned_not_arbitrary_messages(self):
        for case,data in [('version',b'Mihomo Meta v1.19.31 linux amd64 with go1.25.3 2026-10-20\n'),('base',b'configuration test failed\n')]:
            raw,sources=fixture();v=json.loads(raw[case+'.exec.json']);raw[case+'.stdout']=data;v['stdout'].update(bytes=len(data),totalBytes=len(data),sha256=hashed(data));raw[case+'.exec.json']=wire(v)
            with self.assertRaises(ValueError):C.verify_raw(raw,sources,COMMIT)
        # Same five-line protocol as the actual 632 originals. The only allowed
        # final line is relative config.yaml; rehashing a different path cannot
        # turn it into safe output, including the formerly inferred absolute one.
        for case in ('base','candidate'):
            raw,sources=fixture()
            self.assertEqual(raw[case+'.stdout'].splitlines()[-1],b'configuration file config.yaml test is successful')
            C.safe_stdio(case,raw[case+'.stdout'],raw[case+'.stderr'])
            for path in ('/tmp/mihomo-compat-home/'+case+'/config.yaml','/arbitrary/config.yaml','./config.yaml','other.yaml','config.yaml/../secret'):
                changed=raw[case+'.stdout'].replace(b'configuration file config.yaml test is successful\n',('configuration file '+path+' test is successful\n').encode())
                candidate=copy.deepcopy(raw);v=json.loads(candidate[case+'.exec.json']);candidate[case+'.stdout']=changed
                v['stdout'].update(bytes=len(changed),totalBytes=len(changed),sha256=hashed(changed));candidate[case+'.exec.json']=wire(v)
                with self.assertRaises(ValueError):C.verify_raw(candidate,sources,COMMIT)

    def test_go_missing_subtest_or_duplicate_test_rejects(self):
        for duplicate in (False,True):
            raw,sources=fixture();ev=[json.loads(line) for line in raw['compat.json'].splitlines()]
            if duplicate:ev.insert(2,copy.deepcopy(ev[1]))
            else:ev=[e for e in ev if e.get('Test')!=C.SUB[0]]
            raw['compat.json']=b''.join(wire(e) for e in ev)
            with self.assertRaises(ValueError):C.verify_raw(raw,sources,COMMIT)

    def test_go_skip_failure_unknown_test_and_private_output_reject(self):
        for action in ('skip','fail','unknown','output'):
            raw,sources=fixture();ev=[json.loads(line) for line in raw['compat.json'].splitlines()];bad=dict(Action=action,Package='chengwang/internal/mihomodeploy',Test=C.TOP[0])
            if action=='output':bad['Output']='secret: PRIVATE\n'
            ev.insert(2,bad);raw['compat.json']=b''.join(wire(e) for e in ev)
            with self.assertRaises(ValueError):C.verify_raw(raw,sources,COMMIT)

    def test_extra_exec_field_cannot_hide_private_body(self):
        self.reject_json('base.exec.json',lambda d:d.__setitem__('privateBody','PRIVATE'))

    def test_duplicate_json_keys_and_nonfinite_numbers_reject(self):
        for raw in (b'{"schema":1,"schema":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):C.decode(raw)

    def test_source_declared_test_or_contract_shape_drift_reject(self):
        raw,sources=fixture();sources['chengwang/internal/mihomodeploy/runtime_compat_linux_test.go']=b'//go:build linux\n'
        with self.assertRaises(ValueError):C.verify_raw(raw,sources,COMMIT)
        raw,sources=fixture();v=json.loads(sources[C.PREFIX+'compat_contract.json']);v['execKeys'].append('privateBody');sources[C.PREFIX+'compat_contract.json']=wire(v)
        with self.assertRaises(ValueError):C.verify_raw(raw,sources,COMMIT)

    def test_read_rejects_hardlinked_or_oversized_original(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input';p.write_bytes(b'original');os.link(p,Path(d)/'alias')
            with self.assertRaises(ValueError):C.read(p,65536)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input';p.write_bytes(b'oversized')
            with self.assertRaises(ValueError):C.read(p,1)


if __name__ == '__main__': unittest.main()
