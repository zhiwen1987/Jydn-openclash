import json
import pathlib
import tempfile
import unittest

import uid_probe_diagnostic as D


SOURCE = "1" * 40
DIGEST = "2" * 64


class UIDProbeDiagnosticTests(unittest.TestCase):
    def paths(self, directory):
        root = pathlib.Path(directory); root.chmod(0o700)
        return root / "journal.json", root / "uid-probe-diagnostic.json"

    def init(self, journal, host="BOTH_INACCESSIBLE", host_status=43, setup=0, bridge="BRIDGE_ACCESSIBLE", bridge_status=0):
        D.initialize(journal, SOURCE, "321", "7")
        D.set_host_preflight(journal, SOURCE, "321", "7", host, host_status)
        D.set_bridge_setup(journal, SOURCE, "321", "7", setup, DIGEST)
        if setup == 0: D.set_bridge_preflight(journal, SOURCE, "321", "7", bridge, bridge_status)

    def event(self, journal, mode, code=0): D.add_event(journal, SOURCE, "321", "7", mode, code)
    def terminal(self, journal, cleanup=0, absence=0):
        D.set_bridge_terminal(journal, SOURCE, "321", "7", "bridgeCleanupExitStatus", cleanup)
        D.set_bridge_terminal(journal, SOURCE, "321", "7", "bridgeFinalAbsenceExitStatus", absence)

    def test_host_inaccessible_bridge_success_is_canonical_bounded_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            journal, output = self.paths(directory); self.init(journal)
            for mode in D.MODES: self.event(journal, mode)
            self.terminal(journal); D.finalize(journal, output, SOURCE, "321", "7", 0)
            raw=output.read_bytes();value=json.loads(raw)
            self.assertLessEqual(len(raw),4096);self.assertEqual(value["schema"],D.SCHEMA);self.assertEqual(value["probeStatus"],"PASS")
            self.assertEqual(value["hostPreflightClassification"],"BOTH_INACCESSIBLE");self.assertEqual(value["bridgePreflightClassification"],"BRIDGE_ACCESSIBLE")
            self.assertEqual([event["mode"] for event in value["events"]],list(D.MODES))

    def test_setup_and_bridge_preflight_failures_are_bounded_and_cannot_green(self):
        for name,setup,classification,status,want in (("setup",19,None,None,19),("preflight",0,"BRIDGE_PAYLOAD_NOT_READABLE",42,42)):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as directory:
                journal,output=self.paths(directory);self.init(journal,setup=setup,bridge=classification,bridge_status=status)
                self.terminal(journal);D.finalize(journal,output,SOURCE,"321","7",want)
                value=json.loads(output.read_bytes());self.assertEqual(value["probeStatus"],"FAIL");self.assertEqual(value["events"],[])
                with self.assertRaises(ValueError):D.finalize(journal,output.with_name("bad"),SOURCE,"321","7",0)

    def test_probe_prefix_and_two_cleanup_layers_preserve_first_nonzero(self):
        cases=(("root-setup",17,0,0,17),("uid-prepublish-denials",23,0,0,23),("uid-final-read-and-rename",24,0,0,24),("uid-install-replacement",25,0,0,25),("root-cleanup",31,0,0,31),("root-final-absence",32,0,0,32),(None,0,33,0,33),(None,0,0,34,34))
        for failed,code,bridge_cleanup,bridge_absence,want in cases:
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as directory:
                journal,output=self.paths(directory);self.init(journal)
                for mode in D.NORMAL:
                    self.event(journal,mode,code if mode==failed else 0)
                    if mode==failed:break
                self.event(journal,"root-cleanup",code if failed=="root-cleanup" else 0)
                self.event(journal,"root-final-absence",code if failed=="root-final-absence" else 0)
                self.terminal(journal,bridge_cleanup,bridge_absence);D.finalize(journal,output,SOURCE,"321","7",want)
                self.assertEqual(json.loads(output.read_bytes())["finalExitStatus"],want)
        for wrong in (True,0,8):
            with self.subTest(root_setup_wrong_final=wrong),tempfile.TemporaryDirectory() as directory:
                journal,output=self.paths(directory);self.init(journal);self.event(journal,"root-setup",17);self.event(journal,"root-cleanup");self.event(journal,"root-final-absence");self.terminal(journal)
                with self.assertRaises(ValueError):D.finalize(journal,output,SOURCE,"321","7",wrong)

    def test_fixed_enums_order_binding_and_bool_status_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            journal,_=self.paths(directory);D.initialize(journal,SOURCE,"321","7")
            with self.assertRaises(ValueError):D.set_host_preflight(journal,SOURCE,"321","7","/private/path",43)
            with self.assertRaises(ValueError):D.set_host_preflight(journal,SOURCE,"321","7","BOTH_INACCESSIBLE",42)
            D.set_host_preflight(journal,SOURCE,"321","7","BOTH_INACCESSIBLE",43)
            with self.assertRaises(ValueError):D.set_bridge_setup(journal,SOURCE,"321","7",True,DIGEST)
            with self.assertRaises(ValueError):D.set_bridge_setup(journal,"3"*40,"321","7",0,DIGEST)
            with self.assertRaises(ValueError):D.set_bridge_setup(journal,SOURCE,"322","7",0,DIGEST)
            with self.assertRaises(ValueError):D.set_bridge_setup(journal,SOURCE,"321","8",0,DIGEST)

    def test_duplicate_out_of_order_foreign_and_preexisting_output_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            journal,_=self.paths(directory);self.init(journal)
            with self.assertRaises(ValueError):self.event(journal,"unknown")
            with self.assertRaises(ValueError):self.event(journal,"root-finalize")
            self.event(journal,"root-setup")
            with self.assertRaises(ValueError):self.event(journal,"root-setup")
            self.event(journal,"root-cleanup");self.event(journal,"root-final-absence");self.terminal(journal)
        with tempfile.TemporaryDirectory() as directory:
            journal,_=self.paths(directory);self.init(journal);self.terminal(journal)
            with self.assertRaises(ValueError):self.event(journal,"root-setup")
        with tempfile.TemporaryDirectory() as directory:
            journal,_=self.paths(directory);D.initialize(journal,SOURCE,"321","7");D.set_bridge_terminal(journal,SOURCE,"321","7","bridgeCleanupExitStatus",0)
            with self.assertRaises(ValueError):D.set_host_preflight(journal,SOURCE,"321","7","BOTH_INACCESSIBLE",43)
        with tempfile.TemporaryDirectory() as directory:
            journal,_=self.paths(directory);D.initialize(journal,SOURCE,"321","7");D.set_host_preflight(journal,SOURCE,"321","7","BOTH_INACCESSIBLE",43);D.set_bridge_terminal(journal,SOURCE,"321","7","bridgeCleanupExitStatus",0)
            with self.assertRaises(ValueError):D.set_bridge_setup(journal,SOURCE,"321","7",0,DIGEST)
        with tempfile.TemporaryDirectory() as directory:
            journal,_=self.paths(directory);D.initialize(journal,SOURCE,"321","7");D.set_host_preflight(journal,SOURCE,"321","7","BOTH_INACCESSIBLE",43);D.set_bridge_setup(journal,SOURCE,"321","7",0,DIGEST);D.set_bridge_terminal(journal,SOURCE,"321","7","bridgeCleanupExitStatus",0)
            with self.assertRaises(ValueError):D.set_bridge_preflight(journal,SOURCE,"321","7","BRIDGE_ACCESSIBLE",0)
        with tempfile.TemporaryDirectory() as directory:
            journal,output=self.paths(directory);self.init(journal);self.terminal(journal)
            with self.assertRaises(ValueError):D.finalize(journal,output,SOURCE,"321","7",17)
        with tempfile.TemporaryDirectory() as directory:
            journal,output=self.paths(directory);self.init(journal)
            for mode in D.MODES:self.event(journal,mode)
            self.terminal(journal)
            output.write_text("sentinel",encoding="utf-8")
            with self.assertRaises(FileExistsError):D.finalize(journal,output,SOURCE,"321","7",0)
            self.assertEqual(output.read_text("utf-8"),"sentinel")

    def test_diagnostic_contains_no_path_error_or_nonce(self):
        with tempfile.TemporaryDirectory() as directory:
            journal,output=self.paths(directory);self.init(journal)
            for mode in D.MODES:self.event(journal,mode)
            self.terminal(journal);D.finalize(journal,output,SOURCE,"321","7",0)
            raw=output.read_bytes()
            for forbidden in (b"/tmp/",b"\\",b"Traceback",b"nonce",b"runnerDevice",b"runnerInode"):self.assertNotIn(forbidden,raw)


if __name__ == "__main__": unittest.main()
