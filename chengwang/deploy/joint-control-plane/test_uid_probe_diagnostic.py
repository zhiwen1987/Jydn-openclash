import json
import pathlib
import tempfile
import unittest

import uid_probe_diagnostic as D


SOURCE = "1" * 40


class UIDProbeDiagnosticTests(unittest.TestCase):
    def paths(self, directory):
        root = pathlib.Path(directory)
        root.chmod(0o700)
        return root / "journal.json", root / "uid-probe-diagnostic.json"

    def init(self, journal):
        D.initialize(journal, SOURCE, "321", "7")
        D.set_preflight(journal, SOURCE, "321", "7", "BOTH_ACCESSIBLE")

    def event(self, journal, mode, code=0):
        D.add_event(journal, SOURCE, "321", "7", mode, code)

    def test_success_is_canonical_bounded_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            journal, output = self.paths(directory); self.init(journal)
            for mode in D.MODES: self.event(journal, mode)
            D.finalize(journal, output, SOURCE, "321", "7", 0)
            raw = output.read_bytes(); value = json.loads(raw)
            self.assertLessEqual(len(raw), 4096); self.assertEqual(value["probeStatus"], "PASS")
            self.assertEqual([event["mode"] for event in value["events"]], list(D.MODES))

    def test_root_setup_failure_still_requires_cleanup_and_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            journal, output = self.paths(directory); self.init(journal)
            self.event(journal, "root-setup", 17); self.event(journal, "root-cleanup", 0); self.event(journal, "root-final-absence", 0)
            D.finalize(journal, output, SOURCE, "321", "7", 17)
            self.assertEqual(json.loads(output.read_bytes())["probeStatus"], "FAIL")

    def test_uid_first_and_rename_failures_keep_cleanup(self):
        for failed in ("uid-prepublish-denials", "uid-final-read-and-rename", "uid-install-replacement"):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                journal, output = self.paths(directory); self.init(journal)
                for mode in D.NORMAL:
                    self.event(journal, mode, 23 if mode == failed else 0)
                    if mode == failed: break
                self.event(journal, "root-cleanup", 0); self.event(journal, "root-final-absence", 0)
                D.finalize(journal, output, SOURCE, "321", "7", 23)

    def test_cleanup_and_final_absence_failures_are_each_retained(self):
        for failed in D.CLEANUP:
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                journal, output = self.paths(directory); self.init(journal)
                for mode in D.NORMAL: self.event(journal, mode)
                self.event(journal, "root-cleanup", 31 if failed == "root-cleanup" else 0)
                self.event(journal, "root-final-absence", 32 if failed == "root-final-absence" else 0)
                expected=31 if failed=="root-cleanup" else 32
                D.finalize(journal, output, SOURCE, "321", "7", expected)
                value=json.loads(output.read_bytes());self.assertEqual(value["events"][-2 if failed=="root-cleanup" else -1]["outcome"],"FAIL")
            with self.subTest(failed=failed,wrong_final=1), tempfile.TemporaryDirectory() as directory:
                journal, output = self.paths(directory); self.init(journal)
                for mode in D.NORMAL: self.event(journal, mode)
                self.event(journal, "root-cleanup", 31 if failed == "root-cleanup" else 0)
                self.event(journal, "root-final-absence", 32 if failed == "root-final-absence" else 0)
                with self.assertRaises(ValueError):D.finalize(journal, output, SOURCE, "321", "7", 1)

    def test_out_of_order_duplicate_unknown_and_after_terminal_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            journal, _ = self.paths(directory); self.init(journal)
            with self.assertRaises(ValueError): self.event(journal, "root-setup", True)
            for mode in ("root-finalize", "unknown"):
                with self.subTest(mode=mode), self.assertRaises(ValueError): self.event(journal, mode)
            self.event(journal, "root-setup")
            with self.assertRaises(ValueError): self.event(journal, "root-setup")
            self.event(journal, "root-cleanup"); self.event(journal, "root-final-absence")
            with self.assertRaises(ValueError): self.event(journal, "root-finalize")

    def test_foreign_source_run_attempt_and_preexisting_output_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            journal, output = self.paths(directory); self.init(journal)
            with self.assertRaises(ValueError): D.add_event(journal, "2"*40, "321", "7", "root-setup", 0)
            with self.assertRaises(ValueError): D.add_event(journal, SOURCE, "322", "7", "root-setup", 0)
            for mode in D.MODES: self.event(journal, mode)
            output.write_text("sentinel", encoding="utf-8")
            with self.assertRaises(FileExistsError): D.finalize(journal, output, SOURCE, "321", "7", 0)
            self.assertEqual(output.read_text("utf-8"), "sentinel")

    def test_preflight_is_fixed_enum_and_contains_no_path_or_error(self):
        for classification in D.PREFLIGHT:
            with self.subTest(classification=classification), tempfile.TemporaryDirectory() as directory:
                journal, _ = self.paths(directory); D.initialize(journal, SOURCE, "321", "7")
                D.set_preflight(journal, SOURCE, "321", "7", classification)
                raw=journal.read_bytes();self.assertNotIn(b"/tmp/",raw);self.assertNotIn(b"\\\\",raw);self.assertNotIn(b"Traceback",raw)
        with tempfile.TemporaryDirectory() as directory:
            journal, _=self.paths(directory);D.initialize(journal,SOURCE,"321","7")
            with self.assertRaises(ValueError):D.set_preflight(journal,SOURCE,"321","7","/private/path")

    def test_final_exit_cannot_turn_failure_green(self):
        with tempfile.TemporaryDirectory() as directory:
            journal, output = self.paths(directory); self.init(journal)
            self.event(journal,"root-setup",9);self.event(journal,"root-cleanup");self.event(journal,"root-final-absence")
            with self.assertRaises(ValueError):D.finalize(journal,output,SOURCE,"321","7",True)
            with self.assertRaises(ValueError):D.finalize(journal,output,SOURCE,"321","7",0)
            with self.assertRaises(ValueError):D.finalize(journal,output,SOURCE,"321","7",8)


if __name__ == "__main__": unittest.main()
