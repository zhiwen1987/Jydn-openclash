import hashlib
import json
import pathlib
import tempfile
import unittest

import check_uid_probe_diagnostic as C
import uid_probe_diagnostic as D


SOURCE="1"*40
DIGEST="2"*64


def valid():
    value={"schema":C.SCHEMA,"authority":"NON_AUTHORITATIVE","diagnosticOnly":True,"sourceCommit":SOURCE,"runId":"321","runAttempt":"7","hostPreflightScope":C.PREFLIGHT_SCOPE,"hostPreflightClassification":"BOTH_INACCESSIBLE","hostPreflightExitStatus":43,"bridgePreflightScope":C.BRIDGE_PREFLIGHT_SCOPE,"bridgePreflightClassification":"BRIDGE_ACCESSIBLE","bridgePreflightExitStatus":0,"bridgePayloadSetSHA256":DIGEST,"bridgeSetupExitStatus":0,"bridgeCleanupExitStatus":0,"bridgeFinalAbsenceExitStatus":0,"events":[],"probeStatus":"PASS","finalExitStatus":0}
    for mode in C.NORMAL+C.CLEANUP:value["events"].append({"mode":mode,"exitStatus":0,"outcome":"PASS"})
    return value


def raw(value):return (json.dumps(value,separators=(",",":"),sort_keys=True)+"\n").encode()


class UIDProbeCheckerTests(unittest.TestCase):
    def test_valid_host_inaccessible_bridge_pass_and_failed_prefix(self):
        self.assertEqual(C.validate(raw(valid()),SOURCE,"321","7"),raw(valid()))
        value=valid();value["events"]=value["events"][:2]+value["events"][-2:];value["events"][1]={"mode":"uid-prepublish-denials","exitStatus":8,"outcome":"FAIL"};value["probeStatus"]="FAIL";value["finalExitStatus"]=8
        C.validate(raw(value),SOURCE,"321","7")

    def test_setup_preflight_cleanup_and_absence_failures_validate_only_with_exact_first_status(self):
        cases=(("setup",19),("preflight",42),("bridgeCleanupExitStatus",31),("bridgeFinalAbsenceExitStatus",32))
        for kind,code in cases:
            with self.subTest(kind=kind):
                value=valid();value["probeStatus"]="FAIL";value["finalExitStatus"]=code
                if kind=="setup":value["bridgeSetupExitStatus"]=code;value["bridgePreflightClassification"]=None;value["bridgePreflightExitStatus"]=None;value["events"]=[]
                elif kind=="preflight":value["bridgePreflightClassification"]="BRIDGE_PAYLOAD_NOT_READABLE";value["bridgePreflightExitStatus"]=code;value["events"]=[]
                else:value[kind]=code
                C.validate(raw(value),SOURCE,"321","7")
                value["finalExitStatus"]=1
                with self.assertRaises(ValueError):C.validate(raw(value),SOURCE,"321","7")

    def test_foreign_binding_schema_scope_enum_digest_bool_and_extra_reject(self):
        mutations=[]
        for field,replacement in (("sourceCommit","3"*40),("schema","chengwang.joint-uid-probe-diagnostic/v1"),("hostPreflightScope","OTHER"),("bridgePreflightScope","OTHER"),("bridgePreflightClassification","BOTH_ACCESSIBLE"),("bridgePayloadSetSHA256","2"*63),("bridgeSetupExitStatus",True),("finalExitStatus",False)):
            value=valid();value[field]=replacement;mutations.append(value)
        value=valid();value["runId"]="322";mutations.append(value)
        value=valid();value["runAttempt"]="8";mutations.append(value)
        value=valid();value["events"][0]["mode"]="unknown";mutations.append(value)
        value=valid();value["privatePath"]="/secret";mutations.append(value)
        for value in mutations:
            with self.assertRaises(ValueError):C.validate(raw(value),SOURCE,"321","7")
        with self.assertRaises(ValueError):C.validate(json.dumps(valid(),indent=2).encode()+b"\n",SOURCE,"321","7")

    def test_out_of_order_duplicate_missing_cleanup_and_false_green_reject(self):
        mutations=[]
        value=valid();value["events"][0],value["events"][1]=value["events"][1],value["events"][0];mutations.append(value)
        value=valid();value["events"][1]=dict(value["events"][0]);mutations.append(value)
        value=valid();value["events"]=value["events"][:-1];mutations.append(value)
        value=valid();value["bridgeCleanupExitStatus"]=31;mutations.append(value)
        value=valid();value["bridgeFinalAbsenceExitStatus"]=32;mutations.append(value)
        value=valid();value["hostPreflightClassification"]="PREFLIGHT_EXECUTION_FAILED";value["hostPreflightExitStatus"]=44;mutations.append(value)
        value=valid();value["events"]=[];value["probeStatus"]="FAIL";value["finalExitStatus"]=17;mutations.append(value)
        for value in mutations:
            with self.assertRaises(ValueError):C.validate(raw(value),SOURCE,"321","7")

    def test_oversize_and_cli_publication_fail_closed(self):
        with self.assertRaises(ValueError):C.validate(b"{"+b"x"*4096+b"}\n",SOURCE,"321","7")
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);root.chmod(0o700);journal=root/"journal";candidate=root/"candidate";public=root/"public"
            D.initialize(journal,SOURCE,"321","7");D.set_host_preflight(journal,SOURCE,"321","7","BOTH_INACCESSIBLE",43);D.set_bridge_setup(journal,SOURCE,"321","7",0,DIGEST);D.set_bridge_preflight(journal,SOURCE,"321","7","BRIDGE_ACCESSIBLE",0)
            for mode in D.MODES:D.add_event(journal,SOURCE,"321","7",mode,0)
            D.set_bridge_terminal(journal,SOURCE,"321","7","bridgeCleanupExitStatus",0);D.set_bridge_terminal(journal,SOURCE,"321","7","bridgeFinalAbsenceExitStatus",0);D.finalize(journal,candidate,SOURCE,"321","7",0)
            canonical=C.validate(candidate.read_bytes(),SOURCE,"321","7");C.write_new(public,canonical)
            with self.assertRaises(FileExistsError):C.write_new(public,canonical)
            self.assertEqual(public.read_bytes(),canonical);self.assertEqual(len(hashlib.sha256(pathlib.Path(D.__file__).read_bytes()).hexdigest()),64)


if __name__ == "__main__":unittest.main()
