#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import analyze_rule_redundancy as analysis


class RuleRedundancyAnalysisTests(unittest.TestCase):
    def test_recomputed_counts_match_reviewed_audit(self):
        entries = analysis.all_rule_entries()
        ordered = analysis.ordered_repository_entries()
        candidates = analysis.duplicate_candidates(ordered)
        shadows = analysis.shadowed_entries(ordered)
        self.assertEqual(len(entries), 531)
        self.assertEqual(sum(row.matcher_kind != "unsupported" for row in entries), 516)
        self.assertEqual(len(candidates), 147)
        self.assertEqual(len(shadows), 270)

    def test_complete_candidates_are_same_route_static_covers(self):
        ordered = analysis.ordered_repository_entries()
        duplicates = analysis.duplicate_candidates(ordered)
        candidates = analysis.shadowed_entries(ordered)
        self.assertEqual(len(duplicates), 147)
        self.assertEqual(len(candidates), 270)
        candidate_keys = {(later.path, later.line) for later, _ in candidates}
        for later, keep in candidates:
            self.assertEqual(later.route, keep.route)
            self.assertIsNotNone(later.route)
            self.assertTrue(
                keep.provider_order < later.provider_order
                or (keep.provider_order == later.provider_order and keep.line < later.line)
            )
            self.assertTrue(analysis.covers(keep, later))
            self.assertNotIn((keep.path, keep.line), candidate_keys)

    def test_every_rule_has_one_decision_and_private_values_are_redacted(self):
        entries = analysis.all_rule_entries()
        ordered = analysis.ordered_repository_entries()
        inventory = analysis.decision_inventory(entries,
                                                analysis.duplicate_candidates(ordered),
                                                analysis.shadowed_entries(ordered))
        self.assertEqual(len(inventory), len(entries))
        self.assertEqual(len({(row["path"], row["line"]) for row in inventory}), len(entries))
        self.assertEqual(len({row["id"] for row in inventory}), len(entries))
        private = [row for row in inventory if row["path"].endswith("webrtc-client.yaml")]
        self.assertEqual(len(private), 2)
        self.assertTrue(all(row.get("entry_redacted") is True for row in private))
        self.assertTrue(all("entry" not in row for row in private))

    def test_hypothetical_after_is_in_memory_and_rules_remain_unchanged(self):
        candidates = analysis.shadowed_entries(analysis.ordered_repository_entries())
        before_files, after_files = analysis.remove_candidate_lines(candidates)
        self.assertEqual(set(before_files), set(after_files))
        self.assertGreater(sum(map(len, before_files.values())),
                           sum(map(len, after_files.values())))
        for relative, before in before_files.items():
            self.assertEqual((ROOT / relative).read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
