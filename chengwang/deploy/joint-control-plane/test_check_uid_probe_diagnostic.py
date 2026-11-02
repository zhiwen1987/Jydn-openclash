import hashlib
import json
import pathlib
import tempfile
import unittest

import check_uid_probe_diagnostic as C
import uid_probe_diagnostic as D


SOURCE="1"*40


def valid():
    value={"schema":C.SCHEMA,"authority":"NON_AUTHORITATIVE","diagnosticOnly":True,"sourceCommit":SOURCE,"runId":"321","runAttempt":"7","preflightScope":C.PREFLIGHT_SCOPE,"preflightClassification":"BOTH_ACCESSIBLE","events":[],"probeStatus":"PASS","finalExitStatus":0}
    for mode in C.NORMAL+C.CLEANUP:value["events"].append({"mode":mode,"exitStatus":0,"outcome":"PASS"})
    return value


def raw(value):return (json.dumps(value,separators=(",",":"),sort_keys=True)+"\n").encode()


class UIDProbeCheckerTests(unittest.TestCase):
    def test_valid_pass_and_failed_prefix(self):
        self.assertEqual(C.validate(raw(valid()),SOURCE,"321","7"),raw(valid()))
        value=valid();value["events"]=value["events"][:2]+value["events"][-2:]
        value["events"][1]={"mode":"uid-prepublish-denials","exitStatus":8,"outcome":"FAIL"};value["probeStatus"]="FAIL";value["finalExitStatus"]=8
        C.validate(raw(value),SOURCE,"321","7")
        for mode,code in (("root-cleanup",31),("root-final-absence",32)):
            value=valid();event=next(event for event in value["events"] if event["mode"]==mode);event["exitStatus"]=code;event["outcome"]="FAIL";value["probeStatus"]="FAIL";value["finalExitStatus"]=code
            C.validate(raw(value),SOURCE,"321","7")

    def test_foreign_binding_unknown_enum_extra_field_and_noncanonical_reject(self):
        mutations=[]
        value=valid();value["sourceCommit"]="2"*40;mutations.append(value)
        value=valid();value["events"][0]["mode"]="unknown";mutations.append(value)
        value=valid();value["preflightScope"]="CONTRACT_AND_MODULE_LOADABILITY";mutations.append(value)
        value=valid();value["events"][0]["exitStatus"]=True;mutations.append(value)
        value=valid();value["finalExitStatus"]=False;mutations.append(value)
        value=valid();value["privatePath"]="/secret";mutations.append(value)
        for value in mutations:
            with self.subTest(value=value),self.assertRaises(ValueError):C.validate(raw(value),SOURCE,"321","7")
        with self.assertRaises(ValueError):C.validate(json.dumps(valid(),indent=2).encode()+b"\n",SOURCE,"321","7")

    def test_out_of_order_duplicate_missing_cleanup_and_false_green_reject(self):
        mutations=[]
        value=valid();value["events"][0],value["events"][1]=value["events"][1],value["events"][0];mutations.append(value)
        value=valid();value["events"][1]=dict(value["events"][0]);mutations.append(value)
        value=valid();value["events"]=value["events"][:-1];mutations.append(value)
        value=valid();value["events"][2]={"mode":"root-finalize","exitStatus":9,"outcome":"FAIL"};mutations.append(value)
        value=valid();value["events"][2]={"mode":"root-finalize","exitStatus":9,"outcome":"FAIL"};value["probeStatus"]="FAIL";value["finalExitStatus"]=9;mutations.append(value)
        value=valid();value["events"]=value["events"][:2]+value["events"][-2:];value["events"][1]={"mode":"uid-prepublish-denials","exitStatus":8,"outcome":"FAIL"};value["probeStatus"]="FAIL";value["finalExitStatus"]=7;mutations.append(value)
        for mode,code in (("root-cleanup",31),("root-final-absence",32)):
            value=valid();event=next(event for event in value["events"] if event["mode"]==mode);event["exitStatus"]=code;event["outcome"]="FAIL";value["probeStatus"]="FAIL";value["finalExitStatus"]=1;mutations.append(value)
        for value in mutations:
            with self.assertRaises(ValueError):C.validate(raw(value),SOURCE,"321","7")

    def test_oversize_and_secret_text_reject(self):
        with self.assertRaises(ValueError):C.validate(b"{"+b"x"*4096+b"}\n",SOURCE,"321","7")
        value=valid();value["error"]="secret"
        with self.assertRaises(ValueError):C.validate(raw(value),SOURCE,"321","7")

    def test_cli_source_hashes_and_preexisting_publication_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);root.chmod(0o700);journal=root/"journal";candidate=root/"candidate";public=root/"public"
            D.initialize(journal,SOURCE,"321","7");D.set_preflight(journal,SOURCE,"321","7","BOTH_ACCESSIBLE")
            for mode in D.MODES:D.add_event(journal,SOURCE,"321","7",mode,0)
            D.finalize(journal,candidate,SOURCE,"321","7",0)
            canonical=C.validate(candidate.read_bytes(),SOURCE,"321","7")
            C.write_new(public,canonical)
            with self.assertRaises(FileExistsError):C.write_new(public,canonical)
            self.assertEqual(public.read_bytes(),canonical)
            self.assertEqual(len(hashlib.sha256(pathlib.Path(D.__file__).read_bytes()).hexdigest()),64)


if __name__ == "__main__":unittest.main()
