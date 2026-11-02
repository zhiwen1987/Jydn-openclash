#!/usr/bin/env python3
"""Stdlib-only tests for fixed Git roles and replacement-ref immunity."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import check_nativefs_mirror_source as checker
import generate_nativefs_mirror as generator


def _fixture_git(repo: Path, args: list[str], input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env.pop("GIT_NO_REPLACE_OBJECTS", None)
    return subprocess.run(
        [generator._git_executable(), "-C", str(repo), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
        env=env,
        shell=False,
    )


def _line(raw: bytes) -> str:
    return raw.decode("ascii").strip()


class NativeFSMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture_root = os.environ.get("CHENGWANG_NATIVEFS_MIRROR_FIXTURE_ROOT")
        repo = os.environ.get("CHENGWANG_NATIVEFS_MIRROR_REPO")
        if not fixture_root or not repo:
            self.skipTest("explicit external fixture root and exact candidate repo are required")
        root = Path(fixture_root).resolve(strict=True)
        self.case = Path(tempfile.mkdtemp(prefix="nativefs-mirror-", dir=root))
        self.exact_repo = Path(repo).resolve(strict=True)

    def _new_repo(self) -> Path:
        repo = self.case / "repo"
        repo.mkdir()
        _fixture_git(repo, ["init", "--quiet"])
        _fixture_git(repo, ["config", "user.name", "NativeFS Mirror Test"])
        _fixture_git(repo, ["config", "user.email", "nativefs-mirror.invalid"])
        return repo

    def _two_commits(self, repo: Path) -> tuple[str, str, str, str, str, str]:
        source = repo / "source.go"
        source.write_bytes(b"original\n")
        _fixture_git(repo, ["add", "source.go"])
        _fixture_git(repo, ["commit", "--quiet", "-m", "original"])
        commit1 = _line(_fixture_git(repo, ["rev-parse", "HEAD"]).stdout)
        tree1 = _line(_fixture_git(repo, ["rev-parse", "HEAD^{tree}"]).stdout)
        blob1 = _line(_fixture_git(repo, ["rev-parse", "HEAD:source.go"]).stdout)
        source.write_bytes(b"replacement\n")
        _fixture_git(repo, ["add", "source.go"])
        _fixture_git(repo, ["commit", "--quiet", "-m", "replacement"])
        commit2 = _line(_fixture_git(repo, ["rev-parse", "HEAD"]).stdout)
        tree2 = _line(_fixture_git(repo, ["rev-parse", "HEAD^{tree}"]).stdout)
        blob2 = _line(_fixture_git(repo, ["rev-parse", "HEAD:source.go"]).stdout)
        return commit1, tree1, blob1, commit2, tree2, blob2

    def test_fixed_roles_and_exact_render(self) -> None:
        recorder: list[tuple[list[str], dict[str, str]]] = []
        raw = generator.expected_output(self.exact_repo, recorder)
        self.assertEqual(generator.EXPECTED_OUTPUT_BYTES, len(raw))
        self.assertTrue(recorder)
        for argv, env in recorder:
            self.assertEqual("--no-replace-objects", argv[1])
            self.assertEqual("1", env["GIT_NO_REPLACE_OBJECTS"])

    def test_source_policy_rejects_either_removed_defense(self) -> None:
        source_path = Path(generator.__file__)
        source = source_path.read_text(encoding="utf-8")
        for name, old, new in (
            ("argv-defense", '"--no-replace-objects"', '"--replacement-defense-removed"'),
            ("env-defense", 'child_env["GIT_NO_REPLACE_OBJECTS"] = "1"', 'child_env["REMOVED_REPLACE_DEFENSE"] = "1"'),
        ):
            mutant = self.case / f"{name}.py"
            mutant.write_text(source.replace(old, new, 1), encoding="utf-8", newline="\n")
            with self.assertRaises(checker.CheckError):
                checker.check_generator_policy(mutant)

    def test_commit_replacement_is_effective_but_protected_reads_are_raw(self) -> None:
        repo = self._new_repo()
        commit1, tree1, blob1, commit2, tree2, blob2 = self._two_commits(repo)
        self.assertNotEqual((tree1, blob1), (tree2, blob2))
        _fixture_git(repo, ["replace", commit1, commit2])
        unprotected_tree = _line(_fixture_git(repo, ["rev-parse", f"{commit1}^{{tree}}"]).stdout)
        unprotected_blob = _line(_fixture_git(repo, ["rev-parse", f"{commit1}:source.go"]).stdout)
        self.assertEqual(tree2, unprotected_tree)
        self.assertEqual(blob2, unprotected_blob)
        recorder: list[tuple[list[str], dict[str, str]]] = []
        self.assertEqual(tree1, _line(generator._git(repo, ["rev-parse", f"{commit1}^{{tree}}"], recorder)))
        self.assertEqual(blob1, _line(generator._git(repo, ["rev-parse", f"{commit1}:source.go"], recorder)))
        self.assertTrue(all(argv[1] == "--no-replace-objects" and env["GIT_NO_REPLACE_OBJECTS"] == "1" for argv, env in recorder))

    def test_blob_replacement_is_effective_but_protected_read_is_raw(self) -> None:
        repo = self._new_repo()
        original = b"original blob\n"
        replacement = b"replacement blob\n"
        blob1 = _line(_fixture_git(repo, ["hash-object", "-w", "--stdin"], original).stdout)
        blob2 = _line(_fixture_git(repo, ["hash-object", "-w", "--stdin"], replacement).stdout)
        _fixture_git(repo, ["replace", blob1, blob2])
        self.assertEqual(replacement, _fixture_git(repo, ["cat-file", "blob", blob1]).stdout)
        self.assertEqual(original, generator._git(repo, ["cat-file", "blob", blob1]))

    def test_wrong_type_and_missing_replacement_targets_cannot_change_raw_blob(self) -> None:
        for case_name, target_kind in (("wrong-type", "commit"), ("missing", "missing")):
            with self.subTest(case_name):
                repo = self.case / case_name
                repo.mkdir()
                _fixture_git(repo, ["init", "--quiet"])
                original = b"protected original\n"
                blob = _line(_fixture_git(repo, ["hash-object", "-w", "--stdin"], original).stdout)
                replace_dir = repo / ".git/refs/replace"
                replace_dir.mkdir(parents=True)
                if target_kind == "commit":
                    _fixture_git(repo, ["config", "user.name", "NativeFS Mirror Test"])
                    _fixture_git(repo, ["config", "user.email", "nativefs-mirror.invalid"])
                    (repo / "other").write_bytes(b"other\n")
                    _fixture_git(repo, ["add", "other"])
                    _fixture_git(repo, ["commit", "--quiet", "-m", "other"])
                    target = _line(_fixture_git(repo, ["rev-parse", "HEAD"]).stdout)
                else:
                    target = "f" * 40
                (replace_dir / blob).write_text(target + "\n", encoding="ascii", newline="\n")
                unprotected = _fixture_git(repo, ["cat-file", "blob", blob], check=False)
                self.assertNotEqual(0, unprotected.returncode)
                self.assertEqual(original, generator._git(repo, ["cat-file", "blob", blob]))

    def test_generate_is_exclusive_and_verify_is_byte_exact(self) -> None:
        output = self.case / "linux_magic_generated.go"
        self.assertEqual(0, generator.main(["generate", "--repo", str(self.exact_repo), "--output", str(output)]))
        first = output.read_bytes()
        self.assertEqual(generator.EXPECTED_OUTPUT_BYTES, len(first))
        self.assertEqual(1, generator.main(["generate", "--repo", str(self.exact_repo), "--output", str(output)]))
        self.assertEqual(first, output.read_bytes())
        self.assertEqual(0, generator.main(["verify", "--repo", str(self.exact_repo), "--tracked", str(output)]))

    def test_exclusive_writer_rejects_repo_and_git_roots(self) -> None:
        repo = self._new_repo()
        for target in (repo / "forbidden.go", repo / ".git/forbidden.go"):
            with self.assertRaisesRegex(generator.MirrorError, "output_forbidden_root"):
                generator._exclusive_write(repo, target, b"forbidden\n")
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
