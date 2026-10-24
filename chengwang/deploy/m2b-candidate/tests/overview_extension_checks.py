"""Explicit CPU guards; excluded from the frozen legacy test_*.py discovery.

All events in this module are synthetic, never actual Go execution evidence.
"""
from __future__ import annotations

import collections
import contextlib
import io
import json
import pathlib
import re
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

import overview_extension as overview
import run_static_gate


class OverviewIncrementTests(unittest.TestCase):
    def events(self):
        result = []
        for package in sorted(overview.REQUIRED_PACKAGES):
            for pair in sorted(pair for pair in overview.TOP_LEVEL_PAIRS if pair[0] == package):
                result.append(dict(Package=package, Test=pair[1], Action="run"))
                for child in overview.SUBTEST_NAMES.get(pair, ()):
                    result.extend(dict(Package=package, Test=pair[1] + "/" + child, Action=action) for action in ("run", "pass"))
                result.append(dict(Package=package, Test=pair[1], Action="pass"))
            result.append(dict(Package=package, Action="pass"))
        return result

    def transcript(self, directory, events):
        path = pathlib.Path(directory) / "synthetic-not-actual-go.jsonl"
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        return path

    def guarded_legacy(self, stack):
        targets = (overview.capability, overview.capability.access,
                   overview.capability.access.application, overview.capability.access.application.core)
        return [stack.enter_context(mock.patch.object(target, "validate_events")) for target in targets]

    def test_definition_freezes_36_roots_39_pairs_and_old_2670(self):
        overview.definition()
        self.assertEqual(len(overview.TOP_LEVEL_PAIRS), 36)
        self.assertEqual(len(overview.REQUIRED_PAIRS), 39)
        self.assertEqual(overview.fingerprint(overview.REQUIRED_PAIRS), overview.INCREMENT_SHA256)
        self.assertEqual(overview.PRE_SHA256, overview.capability.FULL_SHA256)
        self.assertEqual(overview.FULL_COUNT, 2709)
        self.assertEqual(len(overview.PRE_TERMINAL_PACKAGES), 41)
        self.assertEqual(overview.FULL_TERMINAL_PACKAGES - overview.PRE_TERMINAL_PACKAGES, {overview.NEW_PACKAGE})
        overview.validate_events(self.events())

    def test_static_source_roots_and_three_named_children_match(self):
        module = pathlib.Path(__file__).resolve().parents[3]
        sources = (
            ("internal/overview/provider_test.go", "chengwang/internal/overview"),
            ("internal/api/overview_test.go", "chengwang/internal/api"),
            ("internal/serverruntime/overview_config_test.go", "chengwang/internal/serverruntime"),
            ("internal/serverruntime/overview_runtime_linux_test.go", "chengwang/internal/serverruntime"),
        )
        roots, run_count = set(), 0
        for relative, package in sources:
            raw = (module / relative).read_text(encoding="utf-8")
            roots.update((package, name) for name in re.findall(r"^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)\s*\{", raw, re.M))
            run_count += raw.count("t.Run(")
        self.assertEqual(roots, overview.TOP_LEVEL_PAIRS)
        self.assertEqual(run_count, 1)
        raw = (module / "internal/serverruntime/overview_config_test.go").read_text(encoding="utf-8")
        section = raw.split("func TestLiveOverviewEnvironmentDefaultsDisabled", 1)[1].split("\nfunc Test", 1)[0]
        values = re.search(r"for _, name := range \[\]string\{([^}]+)\}", section)
        self.assertIsNotNone(values)
        self.assertEqual(tuple(re.findall(r'"([a-z]+)"', values[1])), ("unset", "empty", "false"))

    def test_every_missing_or_renamed_increment_is_rejected(self):
        for pair in overview.REQUIRED_PAIRS:
            missing = [e for e in self.events() if (e.get("Package"), e.get("Test")) != pair]
            with self.assertRaises(RuntimeError):
                overview.validate_events(missing)
            renamed = [dict(e, Test=e["Test"] + "Changed") if (e.get("Package"), e.get("Test")) == pair else e for e in self.events()]
            with self.assertRaises(RuntimeError):
                overview.validate_events(renamed)

    def test_wrong_package_and_unreviewed_new_package_tests_reject(self):
        for pair in overview.REQUIRED_PAIRS:
            values = [dict(e, Package="wrong") if (e.get("Package"), e.get("Test")) == pair else e for e in self.events()]
            with self.assertRaises(RuntimeError):
                overview.validate_events(values)
        for name in ("TestUnreviewed", "FuzzUnreviewed/seed#0"):
            with self.assertRaises(RuntimeError):
                overview.validate_events([dict(Package=overview.NEW_PACKAGE, Test=name, Action="run")] + self.events())

    def test_duplicate_run_and_pass_cannot_hide_in_sets(self):
        for pair in overview.REQUIRED_PAIRS:
            for action in ("run", "pass"):
                values = self.events()
                index = next(i for i, e in enumerate(values) if (e.get("Package"), e.get("Test"), e.get("Action")) == (*pair, action))
                values.insert(index, values[index].copy())
                with self.assertRaises(RuntimeError):
                    overview.validate_events(values)

    def test_pass_before_run_and_child_outside_parent_reject(self):
        pair = next(iter(overview.TOP_LEVEL_PAIRS))
        with self.assertRaises(RuntimeError):
            overview.validate_events([dict(Package=pair[0], Test=pair[1], Action="pass")] + self.events())
        root = next(iter(overview.SUBTEST_NAMES))
        child = root[1] + "/unset"
        with self.assertRaises(RuntimeError):
            overview.validate_events([dict(Package=root[0], Test=child, Action="run")] + self.events())

    def test_parent_cannot_pass_before_its_children(self):
        parent = next(iter(overview.SUBTEST_NAMES))
        values = self.events()
        index = next(i for i, e in enumerate(values) if (e.get("Package"), e.get("Test"), e.get("Action")) == (*parent, "run"))
        values.insert(index + 1, dict(Package=parent[0], Test=parent[1], Action="pass"))
        with self.assertRaises(RuntimeError):
            overview.validate_events(values)

    def test_package_terminal_missing_early_or_duplicate_rejects(self):
        for package in overview.REQUIRED_PACKAGES:
            values = [e for e in self.events() if not (e.get("Package") == package and e.get("Test") is None)]
            with self.assertRaises(RuntimeError):
                overview.validate_events(values)
            for extra in ([dict(Package=package, Action="pass")] + self.events(), self.events() + [dict(Package=package, Action="pass")]):
                with self.assertRaises(RuntimeError):
                    overview.validate_events(extra)

    def test_test_and_package_fail_or_skip_always_reject(self):
        for package in overview.REQUIRED_PACKAGES:
            name = next(name for p, name in overview.TOP_LEVEL_PAIRS if p == package)
            for action in ("fail", "skip"):
                for test in (None, name):
                    with self.assertRaises(RuntimeError):
                        overview.validate_events([dict(Package=package, Test=test, Action=action)] + self.events())

    def test_unknown_child_is_not_accepted_or_projected(self):
        package, root = next(iter(overview.SUBTEST_NAMES))
        extra = dict(Package=package, Test=root + "/unreviewed", Action="run")
        with self.assertRaises(RuntimeError):
            overview.validate_events([extra] + self.events())
        self.assertEqual(overview.projected_capability_events([extra]), [extra])

    def test_projection_removes_only_reviewed_pairs_and_new_package_envelope(self):
        package, name = next(pair for pair in overview.REQUIRED_PAIRS if pair[0] != overview.NEW_PACKAGE)
        old = dict(Package=package, Test="TestHistoricalSentinel", Action="run")
        wrong = dict(Package="wrong", Test=name, Action="run")
        terminal = dict(Package=package, Action="pass")
        values = [dict(Package=package, Test=name, Action="run"), old, wrong, terminal,
                  dict(Package=overview.NEW_PACKAGE, Action="start"), dict(Package=overview.NEW_PACKAGE, Action="pass")]
        self.assertEqual(overview.projected_capability_events(values), [old, wrong, terminal])

    def test_legacy_2670_alone_and_substituted_full_names_cannot_pass(self):
        legacy = {"synthetic/legacy": {"TestLegacy" + str(i) for i in range(overview.PRE_COUNT)}}
        with self.assertRaises(RuntimeError):
            overview.split_extension(legacy, overview.PRE_TERMINAL_PACKAGES)
        combined = collections.defaultdict(set, legacy)
        for package, name in overview.REQUIRED_PAIRS:
            combined[package].add(name)
        with self.assertRaisesRegex(RuntimeError, "2709-test"):
            overview.split_extension(combined, overview.FULL_TERMINAL_PACKAGES)

    def test_missing_or_additional_package_scope_rejects_before_hash(self):
        values = collections.defaultdict(set)
        for package, name in overview.REQUIRED_PAIRS:
            values[package].add(name)
        for packages in (overview.PRE_TERMINAL_PACKAGES, overview.FULL_TERMINAL_PACKAGES | {"unreviewed/package"}):
            with self.assertRaisesRegex(RuntimeError, "package scope"):
                overview.split_extension(values, packages)

    def test_transcript_replays_every_original_validator_after_exact_projection(self):
        # Explicit synthetic increment only. Mocking split/legacy validators
        # proves wiring, and does not claim the original 2670 tests ran here.
        values = self.events()
        values.append(dict(Package="chengwang/internal/domain", Action="skip"))
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            path = self.transcript(directory, values)
            split = stack.enter_context(mock.patch.object(overview, "split_extension"))
            checks = self.guarded_legacy(stack)
            overview.validate_transcript(path)
            split.assert_called_once()
            old = overview.projected_capability_events(values)
            checks[0].assert_called_once_with(old)
            access = overview.capability.projected_access_events(old)
            checks[1].assert_called_once_with(access)
            application = overview.capability.access.projected_application_events(access)
            checks[2].assert_called_once_with(application)
            checks[3].assert_called_once_with(overview.capability.access.application.projected_core_events(application))

    def test_all_original_validator_rejections_propagate(self):
        values = self.events() + [dict(Package="chengwang/internal/domain", Action="skip")]
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, values)
            targets = (overview.capability, overview.capability.access,
                       overview.capability.access.application, overview.capability.access.application.core)
            for target in targets:
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(overview, "split_extension"))
                    self.guarded_legacy(stack)
                    stack.enter_context(mock.patch.object(target, "validate_events", side_effect=RuntimeError("synthetic old rejection")))
                    with self.assertRaisesRegex(RuntimeError, "synthetic old rejection"):
                        overview.validate_transcript(path)

    def test_unmocked_synthetic_increment_cannot_pass_complete_transcript(self):
        values = self.events() + [dict(Package="chengwang/internal/domain", Action="skip")]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                overview.validate_transcript(self.transcript(directory, values))

    def test_malformed_identity_duplicate_json_and_nonfinite_values_reject(self):
        for event in ([], dict(Package=[], Action="run"), dict(Package="x", Test=[], Action="run"), dict(Package="x", Action=[])):
            with self.assertRaises(RuntimeError):
                overview.validate_events([event])
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "malformed-synthetic.jsonl"
            for raw in ('{"Action":"run","Action":"pass"}\n', '{"Elapsed":NaN}\n', '[]\n'):
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises((RuntimeError, ValueError)):
                    overview.validate_transcript(path)

    def test_transcript_byte_and_event_budgets_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, self.events())
            with mock.patch.object(overview, "MAX_TRANSCRIPT_BYTES", 10), self.assertRaisesRegex(RuntimeError, "budget"):
                overview.validate_transcript(path)
            with mock.patch.object(overview, "MAX_EVENTS", 1), self.assertRaisesRegex(RuntimeError, "event budget"):
                overview.validate_transcript(path)

    def test_metadata_replacement_or_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, self.events()); original = path.stat()
            fields = {name: getattr(original, name) for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
            for field in ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode"):
                value = stat.S_IFLNK if field == "st_mode" else fields[field] + 1
                changed = types.SimpleNamespace(**dict(fields, **{field: value}))
                with mock.patch.object(pathlib.Path, "lstat", side_effect=[original, changed]), self.assertRaisesRegex(RuntimeError, "custody"):
                    overview.validate_transcript(path)
            descriptor = types.SimpleNamespace(**dict(fields, st_ctime_ns=200))
            named = types.SimpleNamespace(**dict(fields, st_ctime_ns=100))
            self.assertTrue(overview._metadata_stable(descriptor, named, descriptor, named, windows=True))
            self.assertFalse(overview._metadata_stable(descriptor, named, descriptor, named, windows=False))
            for windows in (False, True):
                for change_descriptor in (False, True):
                    descriptor_after = types.SimpleNamespace(**dict(fields, st_ctime_ns=201 if change_descriptor else 200))
                    named_after = types.SimpleNamespace(**dict(fields, st_ctime_ns=100 if change_descriptor else 101))
                    self.assertFalse(overview._metadata_stable(descriptor, named, descriptor_after, named_after, windows=windows))
                for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns"):
                    changed = types.SimpleNamespace(**dict(fields, **{field: fields[field] + 1}, st_ctime_ns=100))
                    self.assertFalse(overview._metadata_stable(descriptor, named, descriptor, changed, windows=windows))

    def test_parent_dispatch_requires_overview_first_and_preserves_legacy_mode(self):
        events = [dict(Package="chengwang/internal/api", Test="TestSyntheticDispatchOnly", Action=a) for a in ("run", "pass")]
        events += [dict(Package="chengwang/internal/api", Action="pass"), dict(Package="chengwang/internal/domain", Action="skip")]
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, events)
            with mock.patch.object(overview, "validate_transcript", side_effect=RuntimeError("synthetic overview reached")) as new, mock.patch.object(overview.capability, "validate_transcript") as old:
                with self.assertRaisesRegex(RuntimeError, "synthetic overview reached"):
                    run_static_gate.validate_go_json([path], probe_extension=True, overview_extension=True)
                new.assert_called_once_with(path.resolve()); old.assert_not_called()
            with mock.patch.object(overview, "validate_transcript") as new, mock.patch.object(overview.capability, "validate_transcript", side_effect=RuntimeError("synthetic legacy reached")) as old:
                with self.assertRaisesRegex(RuntimeError, "synthetic legacy reached"):
                    run_static_gate.validate_go_json([path], probe_extension=True)
                new.assert_not_called(); old.assert_called_once_with(path.resolve())

    def test_cli_flag_is_explicit_and_requires_actual_transcript_input(self):
        for flag, enabled in (([], False), (["--overview-extension"], True)):
            with mock.patch.object(sys, "argv", ["gate", "--go-json", "synthetic.jsonl", *flag]), mock.patch.object(run_static_gate, "validate_go_json", return_value=0) as check:
                self.assertEqual(run_static_gate.main(), 0)
                check.assert_called_once_with([pathlib.Path("synthetic.jsonl")], probe_extension=True, overview_extension=enabled)
        with mock.patch.object(sys, "argv", ["gate", "--overview-extension"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(run_static_gate.main(), 1)
        with self.assertRaisesRegex(RuntimeError, "complete parent"):
            run_static_gate.validate_go_json([], overview_extension=True)
        with self.assertRaisesRegex(RuntimeError, "actual Go JSON"):
            run_static_gate.validate_go_json([], probe_extension=True, overview_extension=True)


if __name__ == "__main__":
    unittest.main()
