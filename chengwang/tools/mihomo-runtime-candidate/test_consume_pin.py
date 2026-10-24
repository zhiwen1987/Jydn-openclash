"""Synthetic CPU-only bytes and explicit mock-Git contracts; no real executable."""
import ast
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zlib

import consume_pin as P
import check_consumption as C

HERE = Path(__file__).parent
REPO = HERE.parents[2]
FAKE_PROJECT_COMMIT = '1' * 40  # Never described as a real committed CLI acceptance.
FROZEN_TEST_COUNT = 47
FROZEN_NAMES_SHA256 = '390ff9bf1c63f9d586de54df624d81fedbaa2258d0e82f39e7108e1063c7c6fc'


def elf(kind=3):
    ident = b'\x7fELF' + bytes((2,1,1,0,0)) + bytes(7)
    header = struct.pack('<16sHHIQQQIHHHHHH',ident,kind,62,1,0x400080,64,0,0,64,56,1,0,0,0)
    program = struct.pack('<IIQQQQQQ',1,5,0,0x400000,0,512,512,4096)
    return header + program + bytes(512 - len(header) - len(program))


def gz(payload=None): return gzip.compress(elf() if payload is None else payload,mtime=0)


def replace(raw, offset, size, value):
    return raw[:offset] + value.to_bytes(size,'little') + raw[offset+size:]


def readers(raw, **kwargs):
    sha = hashlib.sha256(raw).hexdigest()
    return (P.inflate_one(raw,sha,**kwargs),C.original_payload(raw,sha,
        **{ {'compressed_limit':'compressed_max','expanded_limit':'expanded_max'}.get(k,k):v for k,v in kwargs.items()}))


def reject_gzip(case, raw, **kwargs):
    sha = hashlib.sha256(raw).hexdigest()
    for fn, args in ((P.inflate_one,kwargs),(C.original_payload,
        { {'compressed_limit':'compressed_max','expanded_limit':'expanded_max'}.get(k,k):v for k,v in kwargs.items()})):
        with case.subTest(reader=fn.__module__), case.assertRaises(ValueError): fn(raw,sha,**args)


def reject_elf(case, raw):
    for fn in (P.inspect_elf,C.elf_identity):
        with case.subTest(reader=fn.__module__), case.assertRaises(ValueError): fn(raw)


def synthetic_receipt():
    original=gz();payload,facts=P.inflate_one(original,P.sha(original));header=P.inspect_elf(payload)
    source=dict(projectSourceCommit=FAKE_PROJECT_COMMIT,sourceFiles=[],pinSHA256='0'*64)
    record=P.receipt(source,P.load_pin((HERE/'pin.json').read_bytes()),original,payload,facts,header)
    return record,(source,original,payload,facts,header)


class SyntheticConsumptionContracts(unittest.TestCase):
    def test_frozen_name_manifest_matches_declared_methods(self):
        names=sorted(name for name in vars(type(self)) if name.startswith('test_'))
        self.assertEqual(len(names),FROZEN_TEST_COUNT)
        self.assertEqual(hashlib.sha256('\n'.join(names).encode()).hexdigest(),FROZEN_NAMES_SHA256)

    def test_independent_receipt_matches_synthetic_producer(self):
        record,args=synthetic_receipt();raw=P.canonical(record)
        self.assertEqual(C.validate_receipt(raw,*args),raw)

    def test_independent_receipt_rejects_false_as_numeric_zero(self):
        record,args=synthetic_receipt();record['runtimeExecuted']=0
        with self.assertRaises(ValueError):C.validate_receipt(P.canonical(record),*args)

    def test_independent_receipt_rejects_execution_or_production_claim(self):
        for key in ('runtimeExecuted','publisherSignatureProven','productionApproved','production'):
            record,args=synthetic_receipt();record[key]=True
            with self.subTest(flag=key),self.assertRaises(ValueError):C.validate_receipt(P.canonical(record),*args)

    def test_independent_receipt_rejects_unknown_fields(self):
        record,args=synthetic_receipt();record['extra']='not-reviewed'
        with self.assertRaises(ValueError):C.validate_receipt(P.canonical(record),*args)

    def test_independent_receipt_rejects_noncanonical_or_duplicate_json(self):
        record,args=synthetic_receipt();raw=P.canonical(record)
        for changed in (json.dumps(record).encode(),raw+b'\n',b'{"source":0,"source":1}'):
            with self.assertRaises(ValueError):C.validate_receipt(changed,*args)

    def test_independent_receipt_rejects_elf_or_archive_size_hash_tampering(self):
        for field in ('elf','archive'):
            for key,value in (('sha256','0'*64),('bytes',1)):
                record,args=synthetic_receipt();record[field][key]=value
                with self.subTest(field=field,key=key),self.assertRaises(ValueError):C.validate_receipt(P.canonical(record),*args)

    def test_independent_receipt_rejects_wrong_project_source(self):
        record,args=synthetic_receipt();record['source']=dict(record['source'],projectSourceCommit=P.UPSTREAM)
        with self.assertRaises(ValueError):C.validate_receipt(P.canonical(record),*args)

    def test_independent_receipt_rejects_permission_claim_tampering(self):
        record,args=synthetic_receipt();record['output']['mode']='0777'
        with self.assertRaises(ValueError):C.validate_receipt(P.canonical(record),*args)

    def test_single_gzip_and_elf_exec_dyn_agree(self):
        for kind in (2,3):
            binary = elf(kind); outputs = readers(gz(binary))
            self.assertEqual(outputs[0],outputs[1]); self.assertEqual(outputs[0][0],binary)
            self.assertEqual(P.inspect_elf(binary),C.elf_identity(binary))

    def test_exact_published_digest_is_enforced(self):
        raw = gz()
        for fn in (P.inflate_one,C.original_payload):
            with self.subTest(reader=fn.__module__),self.assertRaises(ValueError): fn(raw,P.PUBLISHED_SHA)

    def test_compressed_limit_exact_and_over(self):
        raw = gz(); readers(raw,compressed_limit=len(raw))
        reject_gzip(self,raw,compressed_limit=len(raw)-1)

    def test_expanded_limit_exact_and_over(self):
        raw = gz(); readers(raw,expanded_limit=512)
        reject_gzip(self,raw,expanded_limit=511)

    def test_empty_expansion_is_rejected(self): reject_gzip(self,gz(b''))

    def test_concatenated_members_are_rejected(self): reject_gzip(self,gz()+gz())

    def test_trailing_zero_and_arbitrary_bytes_are_rejected(self):
        for tail in (b'\0',b'\0'*8,b'not-another-member'):
            reject_gzip(self,gz()+tail)

    def test_truncated_header_deflate_and_trailer_are_rejected(self):
        raw = gz()
        for size in (0,3,9,17,len(raw)//2,len(raw)-1,len(raw)-8): reject_gzip(self,raw[:size])

    def test_corrupt_crc_is_rejected(self):
        raw = gz(); reject_gzip(self,raw[:-8]+bytes((raw[-8]^1,))+raw[-7:])

    def test_corrupt_isize_is_rejected(self):
        raw = gz(); reject_gzip(self,raw[:-4]+bytes((raw[-4]^1,))+raw[-3:])

    def test_reserved_gzip_flags_are_rejected(self): reject_gzip(self,replace(gz(),3,1,0x20))

    def test_optional_gzip_headers_and_header_crc(self):
        base = gz(); header = base[:3]+bytes((4|8|16|2,))+base[4:10]
        header += b'\x03\0abcsynthetic\0comment\0'
        header += struct.pack('<H',zlib.crc32(header)&0xffff)
        wrapped = header+base[10:]
        self.assertEqual(readers(wrapped)[0],readers(wrapped)[1])
        corrupt = wrapped[:len(header)-1]+bytes((wrapped[len(header)-1]^1,))+wrapped[len(header):]
        reject_gzip(self,corrupt)

    def test_unterminated_gzip_name_is_rejected(self):
        raw = gz(); reject_gzip(self,raw[:3]+b'\x08'+raw[4:10]+b'nonterminated')

    def test_non_deflate_gzip_method_is_rejected(self): reject_gzip(self,replace(gz(),2,1,0))

    def test_elf_magic_and_word_size_are_rejected(self):
        for off,value in ((0,0),(4,1),(5,2),(6,0),(7,9),(8,1)): reject_elf(self,replace(elf(),off,1,value))

    def test_elf_wrong_machine_type_and_version_are_rejected(self):
        for off,size,value in ((16,2,1),(18,2,183),(20,4,0),(48,4,1)): reject_elf(self,replace(elf(),off,size,value))

    def test_elf_header_and_program_sizes_are_rejected(self):
        for off,size,value in ((52,2,63),(54,2,55),(56,2,0),(56,2,1025),(32,8,32)):
            reject_elf(self,replace(elf(),off,size,value))

    def test_elf_program_table_out_of_bounds_is_rejected(self): reject_elf(self,replace(elf(),32,8,500))

    def test_elf_entry_requires_executable_file_backed_load(self):
        for raw in (replace(elf(),24,8,0),replace(elf(),24,8,0x500000),
                    replace(elf(),68,4,4),replace(elf(),64,4,0)):
            reject_elf(self,raw)

    def test_elf_segment_offset_and_size_are_bounded(self):
        for off,value in ((72,513),(96,513),(104,511),(80,(1<<64)-1)):
            reject_elf(self,replace(elf(),off,8,value))

    def test_elf_segment_alignment_is_checked(self):
        reject_elf(self,replace(elf(),112,8,3))
        reject_elf(self,replace(elf(),80,8,0x400001))

    def test_elf_section_table_is_checked(self):
        reject_elf(self,replace(elf(),40,8,128))
        reject_elf(self,replace(elf(),60,2,1))

    def test_elf_truncated_bytes_are_rejected(self):
        for size in (0,63,64,119,511): reject_elf(self,elf()[:size])

    def test_pin_unknown_sizes_stay_unknown_and_flags_false(self):
        pin = P.load_pin((HERE/'pin.json').read_bytes())
        self.assertIsNone(pin['artifact']['exactCompressedBytes'])
        self.assertIsNone(pin['artifact']['elfSHA256']);self.assertIsNone(pin['artifact']['elfBytes'])
        self.assertFalse(pin['productionApproved']);self.assertFalse(pin['publisherSignatureProven'])

    def test_pin_digest_version_and_boolean_tampering_are_rejected(self):
        pin = json.loads((HERE/'pin.json').read_bytes())
        for path,value in ((('artifact','publishedSHA256'),'0'*64),(('version',),'v0'),(('runtimeExecuted',),0)):
            altered = copy.deepcopy(pin)
            if len(path)==2: altered[path[0]][path[1]]=value
            else: altered[path[0]]=value
            with self.assertRaises(ValueError): P.load_pin(json.dumps(altered).encode())

    def test_duplicate_json_nonfinite_and_nonobject_are_rejected(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}',b'[]'):
            for fn in (P.strict_json,C.decode):
                with self.subTest(reader=fn.__module__),self.assertRaises(ValueError): fn(raw)

    def test_regular_file_readback_and_byte_limit(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'synthetic.gz';p.write_bytes(gz())
            self.assertEqual(P.read_regular(p,1000),C.stable_bytes(p,1000))
            for fn in (P.read_regular,C.stable_bytes):
                with self.assertRaises(ValueError):fn(p,1)

    def test_hardlink_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'one';p.write_bytes(b'synthetic');os.link(p,Path(root)/'two')
            for fn in (P.read_regular,C.stable_bytes):
                with self.assertRaises(ValueError):fn(p,100)

    def test_symlink_or_reparse_path_is_rejected_without_follow(self):
        p=HERE/'pin.json'
        with mock.patch.object(Path,'is_symlink',return_value=True),self.assertRaises(ValueError): P.plain(p)
        old=Path.lstat
        def linked(path,*args,**kwargs):
            s=old(path,*args,**kwargs)
            if path==p.absolute(): return os.stat_result((stat.S_IFLNK|0o777,*s[1:]))
            return s
        with mock.patch.object(Path,'lstat',linked),self.assertRaises(ValueError): C.path_without_links(p)

    def test_changed_descriptor_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'data';p.write_bytes(b'synthetic')
            original=os.fstat
            def changed(fd):
                s=original(fd)
                return os.stat_result((s.st_mode,s.st_ino+1,*s[2:]))
            for fn in (P.read_regular,C.stable_bytes):
                with mock.patch.object(os,'fstat',changed),self.assertRaises(ValueError):fn(p,100)

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'existing';p.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError): P.write_new(p,b'changed',0o500)
            self.assertEqual(p.read_bytes(),b'preserve')

    def test_incorrect_output_permission_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'data';p.write_bytes(b'synthetic')
            wrong=0o500 if stat.S_IMODE(p.stat().st_mode)!=0o500 else 0o400
            for fn in (P.read_regular,C.stable_bytes):
                with self.assertRaises(ValueError): fn(p,100,wrong)

    def test_mock_git_bindings_match_five_host_files_only(self):
        def mocked_git(argv,**kwargs):
            if argv[-2:]==['rev-parse','--show-toplevel']: data=os.fsencode(str(REPO))+b'\n'
            elif argv[-2:]==['rev-parse','HEAD']: data=(FAKE_PROJECT_COMMIT+'\n').encode()
            elif argv[-2:]==['rev-parse','--is-bare-repository']: data=b'false\n'
            else:
                self.assertEqual(argv[-2],'show')
                self.assertTrue(argv[-1].startswith(FAKE_PROJECT_COMMIT+':'))
                data=(REPO/argv[-1].split(':',1)[1]).read_bytes()
            return subprocess.CompletedProcess(argv,0,data,b'')
        with mock.patch.object(subprocess,'run',side_effect=mocked_git):
            source,pin=P.source_bindings(REPO,FAKE_PROJECT_COMMIT)
            independent=C.source_identity(REPO,FAKE_PROJECT_COMMIT)
        self.assertEqual(source,independent);self.assertEqual(len(source['sourceFiles']),5)
        self.assertNotEqual(source['projectSourceCommit'],pin['upstreamSourceCommit'])

    def test_mock_git_wrong_head_is_rejected(self):
        def wrong(argv,**kwargs):
            data=os.fsencode(str(REPO))+b'\n' if argv[-1]=='--show-toplevel' else b'2'*40+b'\n'
            return subprocess.CompletedProcess(argv,0,data,b'')
        with mock.patch.object(subprocess,'run',side_effect=wrong):
            for fn in (P.source_bindings,C.source_identity):
                with self.assertRaises(ValueError):fn(REPO,FAKE_PROJECT_COMMIT)

    def test_mock_git_modified_host_source_is_rejected(self):
        def wrong_blob(argv,**kwargs):
            if argv[-1]=='--show-toplevel':data=os.fsencode(str(REPO))+b'\n'
            elif argv[-1]=='HEAD':data=(FAKE_PROJECT_COMMIT+'\n').encode()
            elif argv[-1]=='--is-bare-repository':data=b'false\n'
            else:data=b'not-host-source'
            return subprocess.CompletedProcess(argv,0,data,b'')
        with mock.patch.object(subprocess,'run',side_effect=wrong_blob):
            for fn in (P.source_bindings,C.source_identity):
                with self.assertRaises(ValueError):fn(REPO,FAKE_PROJECT_COMMIT)

    def test_receipt_reports_actual_synthetic_sizes_and_no_execution(self):
        pin=P.load_pin((HERE/'pin.json').read_bytes());raw=gz();binary,facts=readers(raw)[0]
        record=P.receipt({'projectSourceCommit':FAKE_PROJECT_COMMIT,'sourceFiles':[],'pinSHA256':'0'*64},
            pin,raw,binary,facts,P.inspect_elf(binary))
        self.assertEqual(record['archive']['bytes'],len(raw));self.assertEqual(record['elf']['bytes'],512)
        self.assertFalse(record['runtimeExecuted']);self.assertFalse(record['publisherSignatureProven'])
        self.assertFalse(record['production']);self.assertNotIn('runtimeVersion',record)
        self.assertEqual(P.canonical(record),C.encode(record))

    def test_independent_checker_does_not_import_producer(self):
        t=ast.parse((HERE/'check_consumption.py').read_bytes())
        imports=[n for n in ast.walk(t) if isinstance(n,(ast.Import,ast.ImportFrom))]
        self.assertFalse(any(getattr(n,'module',None)=='consume_pin' or
            any(a.name=='consume_pin' for a in getattr(n,'names',[])) for n in imports))

    def test_nonposix_cli_cannot_claim_posix_mode_evidence(self):
        if os.name!='posix':
            with mock.patch.object(P,'source_bindings') as binding,self.assertRaises(ValueError):
                P.consume(Path('missing.gz'),REPO,FAKE_PROJECT_COMMIT,Path('missing-output'))
            binding.assert_not_called()
        else:
            # Pure contract: an absent original is rejected even with mocked Git.
            pin=P.load_pin((HERE/'pin.json').read_bytes())
            with mock.patch.object(P,'source_bindings',return_value=({},pin)),self.assertRaises(FileNotFoundError):
                P.consume(Path('missing.gz'),REPO,FAKE_PROJECT_COMMIT,Path('missing-output'))


if __name__=='__main__':unittest.main(verbosity=2)
