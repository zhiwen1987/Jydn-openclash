"""Pure CPU, synthetic gate counterexamples; never new Go runtime evidence."""
from __future__ import annotations

import collections
import json
import pathlib
import re
import tempfile
import types
import unittest
from unittest import mock

import capability_truth_extension as truth
import run_static_gate


class CapabilityTruthIncrementTests(unittest.TestCase):
    def events(self):
        values = []
        for package in sorted(truth.REQUIRED_PACKAGES):
            for pair in sorted(p for p in truth.TOP_LEVEL_PAIRS if p[0] == package):
                values.append(dict(Package=package, Test=pair[1], Action="run"))
                for child in truth.SUBTEST_NAMES.get(pair, ()):
                    values.extend(dict(Package=package, Test=pair[1] + "/" + child, Action=action) for action in ("run", "pass"))
                values.append(dict(Package=package, Test=pair[1], Action="pass"))
            values.append(dict(Package=package, Action="pass"))
        return values

    def transcript(self, directory, events):
        path = pathlib.Path(directory) / "synthetic-go-events.jsonl"
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        return path

    def test_synthetic_increment_definition_and_parent_order(self):
        truth.definition()
        self.assertEqual(len(truth.TOP_LEVEL_PAIRS), 14)
        self.assertEqual(len(truth.REQUIRED_PAIRS), 26)
        self.assertEqual(truth.fingerprint(truth.REQUIRED_PAIRS), truth.INCREMENT_SHA256)
        truth.validate_events(self.events())

    def test_source_declared_roots_and_named_subtests_match_frozen_pairs(self):
        module = pathlib.Path(__file__).resolve().parents[3]
        roots = set()
        for suffix in ("capability", "api"):
            raw = (module / "internal" / suffix / "subscription_capabilities_test.go").read_text(encoding="utf-8")
            names = re.findall(r"^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{", raw, re.M)
            roots.update(("chengwang/internal/" + suffix, name) for name in names)
            if suffix == "capability":
                section = raw.split("func TestSubscriptionCapabilityRequiresBackendAndIdentity", 1)[1].split("\nfunc Test", 1)[0]
                children = re.findall(r'\{name: "([a-z ]+)"', section)
            else:
                section = raw.split("func TestSubscriptionCapabilitiesAPIRequiresConfiguredBackendScopeAndIdentity", 1)[1].split("\nfunc Test", 1)[0]
                values = re.search(r'for _, name := range \[\]string\{([^\n]+)\}', section)
                self.assertIsNotNone(values)
                children = re.findall(r'"([a-z ]+)"', values[1])
            parent = next(pair for pair in truth.SUBTEST_NAMES if pair[0] == "chengwang/internal/" + suffix)
            self.assertEqual(tuple(value.replace(" ", "_") for value in children), truth.SUBTEST_NAMES[parent])
            self.assertIn("t.Run(", section)
        self.assertEqual(roots, truth.TOP_LEVEL_PAIRS)

    def test_every_missing_or_renamed_pair_is_rejected(self):
        for pair in truth.REQUIRED_PAIRS:
            for renamed in (False, True):
                values = [event.copy() for event in self.events()]
                if renamed:
                    for event in values:
                        if (event.get("Package"), event.get("Test")) == pair:
                            event["Test"] += "Changed"
                else:
                    values = [event for event in values if (event.get("Package"), event.get("Test")) != pair]
                with self.assertRaises(RuntimeError):
                    truth.validate_events(values)

    def test_wrong_package_is_rejected_for_roots_and_children(self):
        for pair in truth.REQUIRED_PAIRS:
            values = [dict(event, Package="wrong") if (event.get("Package"), event.get("Test")) == pair else event for event in self.events()]
            with self.assertRaises(RuntimeError):
                truth.validate_events(values)

    def test_duplicate_run_or_pass_is_rejected(self):
        for action in ("run", "pass"):
            for pair in truth.REQUIRED_PAIRS:
                values = self.events()
                index = next(i for i, event in enumerate(values) if (event.get("Package"), event.get("Test"), event.get("Action")) == (*pair, action))
                values.insert(index, values[index].copy())
                with self.assertRaises(RuntimeError):
                    truth.validate_events(values)

    def test_test_and_package_skip_or_fail_is_rejected(self):
        for package in truth.REQUIRED_PACKAGES:
            for action in ("fail", "skip"):
                for name in (None, next(name for p, name in truth.REQUIRED_PAIRS if p == package)):
                    with self.assertRaises(RuntimeError):
                        truth.validate_events([dict(Package=package, Test=name, Action=action)] + self.events())

    def test_pass_without_run_or_subtest_outside_parent_is_rejected(self):
        for pair in truth.REQUIRED_PAIRS:
            values = [event for event in self.events() if (event.get("Package"), event.get("Test"), event.get("Action")) != (*pair, "run")]
            with self.assertRaises(RuntimeError):
                truth.validate_events(values)
        parent = next(iter(truth.SUBTEST_NAMES))
        child = parent[1] + "/" + truth.SUBTEST_NAMES[parent][0]
        with self.assertRaises(RuntimeError):
            truth.validate_events([dict(Package=parent[0], Test=child, Action="run")] + self.events())

    def test_parent_cannot_pass_before_its_children(self):
        for pair in truth.SUBTEST_NAMES:
            values = self.events()
            parent_pass = next(event for event in values if (event.get("Package"), event.get("Test"), event.get("Action")) == (*pair, "pass"))
            values.remove(parent_pass)
            index = next(i for i, event in enumerate(values) if (event.get("Package"), event.get("Test"), event.get("Action")) == (*pair, "run"))
            values.insert(index + 1, parent_pass)
            with self.assertRaises(RuntimeError):
                truth.validate_events(values)

    def test_terminal_missing_duplicate_premature_or_followed_by_events_is_rejected(self):
        for package in truth.REQUIRED_PACKAGES:
            for values in (
                [event for event in self.events() if not (event.get("Package") == package and "Test" not in event)],
                [dict(Package=package, Action="pass")] + self.events(),
                self.events() + [dict(Package=package, Action="pass")],
                self.events() + [dict(Package=package, Action="output")],
            ):
                with self.assertRaises(RuntimeError):
                    truth.validate_events(values)

    def test_unreviewed_subtest_is_rejected_and_not_projected(self):
        package, name = next(iter(truth.TOP_LEVEL_PAIRS))
        extra = dict(Package=package, Test=name + "/unreviewed", Action="run")
        with self.assertRaises(RuntimeError):
            truth.validate_events([extra] + self.events())
        self.assertEqual(truth.projected_access_events([extra]), [extra])

    def test_projection_removes_only_exact_reviewed_pairs(self):
        package, name = next(iter(truth.REQUIRED_PAIRS))
        old = dict(Package=package, Test="TestHistoricalSentinel", Action="run")
        wrong = dict(Package="wrong", Test=name, Action="run")
        terminal = dict(Package=package, Action="pass")
        values = [dict(Package=package, Test=name, Action="run"), old, wrong, terminal]
        self.assertEqual(truth.projected_access_events(values), [old, wrong, terminal])

    def test_old_baseline_shape_or_substituted_retained_set_cannot_pass_full_gate(self):
        synthetic_old = {"synthetic/legacy": {"TestLegacy" + str(i) for i in range(truth.PRE_COUNT)}}
        with self.assertRaises(RuntimeError):
            truth.split_extension(synthetic_old, set(truth.REQUIRED_PACKAGES))
        synthetic_full = collections.defaultdict(set, synthetic_old)
        for package, name in truth.REQUIRED_PAIRS:
            synthetic_full[package].add(name)
        with self.assertRaises(RuntimeError):
            truth.split_extension(synthetic_full, set(truth.REQUIRED_PACKAGES))

    def test_transcript_calls_each_original_event_validator_with_exact_projection(self):
        values = self.events()
        projected = truth.projected_access_events(values)
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, values)
            with mock.patch.object(truth.access, "validate_events") as access_check, mock.patch.object(truth.access.application, "validate_events") as application_check, mock.patch.object(truth.access.application.core, "validate_events") as core_check:
                truth.validate_transcript(path)
            access_check.assert_called_once_with(projected)
            application_events = truth.access.projected_application_events(projected)
            application_check.assert_called_once_with(application_events)
            core_check.assert_called_once_with(truth.access.application.projected_core_events(application_events))

    def test_original_validator_rejections_propagate(self):
        targets = (truth.access, truth.access.application, truth.access.application.core)
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, self.events())
            for rejected in targets:
                with mock.patch.object(truth.access, "validate_events"), mock.patch.object(truth.access.application, "validate_events"), mock.patch.object(truth.access.application.core, "validate_events"):
                    with mock.patch.object(rejected, "validate_events", side_effect=RuntimeError("synthetic historical rejection")):
                        with self.assertRaisesRegex(RuntimeError, "synthetic historical rejection"):
                            truth.validate_transcript(path)

    def test_transcript_rejects_duplicate_keys_nonfinite_values_or_nonobjects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "malformed-synthetic.jsonl"
            for raw in ('{"Action":"run","Action":"pass"}\n', '{"Elapsed":NaN}\n', '[]\n'):
                path.write_text(raw, encoding="utf-8")
                with self.assertRaises((RuntimeError, ValueError)):
                    truth.validate_transcript(path)

    def test_transcript_rejects_metadata_changes_during_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, self.events())
            original = path.stat()
            fields = {name: getattr(original, name) for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
            for field in ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
                changed = types.SimpleNamespace(**dict(fields, **{field: fields[field] + 1}))
                for fd_changed in (False, True):
                    fd_after, named_after = (changed, original) if fd_changed else (original, changed)
                    with mock.patch.object(truth.os, "fstat", side_effect=[original, fd_after]), mock.patch.object(pathlib.Path, "stat", side_effect=[original, named_after]):
                        with self.assertRaisesRegex(RuntimeError, "custody changed"):
                            truth.validate_transcript(path)

    def test_malformed_event_identity_types_are_rejected(self):
        for event in (dict(Package=[], Action="run"), dict(Package="package", Test=[], Action="run"), dict(Package="package", Action=[])):
            with self.assertRaisesRegex(RuntimeError, "identity is malformed"):
                truth.validate_events([event])

    def test_parent_cli_branch_requires_new_extension_before_old_baseline(self):
        events = [dict(Package="chengwang/internal/api", Test="TestSyntheticDispatchOnly", Action=action) for action in ("run", "pass")]
        events.append(dict(Package="chengwang/internal/api", Action="pass"))
        events.extend(dict(Package=package, Action="skip") for package in run_static_gate.ALLOWED_GO_PACKAGE_SKIPS)
        with tempfile.TemporaryDirectory() as directory:
            path = self.transcript(directory, events)
            with mock.patch.object(truth, "validate_transcript", side_effect=RuntimeError("synthetic dispatch reached")) as check:
                with self.assertRaisesRegex(RuntimeError, "synthetic dispatch reached"):
                    run_static_gate.validate_go_json([path], probe_extension=True)
                check.assert_called_once_with(path.resolve())


if __name__ == "__main__":
    unittest.main()
