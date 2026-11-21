#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "skills" / "codex-dispatch" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import codex_dispatch as cd  # noqa: E402


class TestScopeAndPatterns(unittest.TestCase):
    def test_anchored_segment_matching(self) -> None:
        self.assertTrue(cd.matches_pattern("src/pay/handler.py", "src/pay/**"))
        self.assertTrue(cd.matches_pattern("src/pay/sub/deep.py", "src/pay/**"))
        self.assertTrue(cd.matches_pattern("src/pay/handler.py", "src/pay"))
        self.assertFalse(cd.matches_pattern("src/payment/handler.py", "src/pay"))
        self.assertTrue(cd.matches_pattern("foo.py", "**/foo.py"))
        self.assertTrue(cd.matches_pattern("a/b/foo.py", "**/foo.py"))
        self.assertTrue(cd.matches_pattern("tests/test_pay.py", "tests/*.py"))
        # Must NOT let single `*` cross directory boundary or suffix-match unanchored paths!
        self.assertFalse(cd.matches_pattern("tests/unit/test_pay.py", "tests/*.py"))
        self.assertFalse(cd.matches_pattern("other/tests/test_pay.py", "tests/*.py"))
        # Outside workspace paths NEVER match even `**`
        self.assertFalse(cd.matches_pattern(f"{cd.OUTSIDE_WS_PREFIX}README.md", "**"))

    def test_whitespace_filenames_and_forbid_precedence(self) -> None:
        parsed = cd.parse_porcelain_entries("??  notes.txt\0?? notes.txt\0")
        self.assertIn(" notes.txt", parsed)
        self.assertIn("notes.txt", parsed)
        self.assertEqual(len(parsed), 2)

        ok, violations = cd.check_scope(
            ["src/pay/core.py", "src/pay/secret.py", "README.md"],
            allow_patterns=["src/pay/**"],
            forbid_patterns=["src/pay/secret.py"],
        )
        self.assertFalse(ok)
        self.assertEqual(len(violations), 2)

    def test_jsonl_u2028_and_incomplete_turn_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "summary.md"
            # Intermediate agent_message WITHOUT turn.completed and without summary.md -> MUST FAIL
            raw_incomplete = (
                '{"type":"thread.started","thread_id":"sid-1"}\n'
                '{"type":"item.completed","item":{"type":"agent_message","text":"Checking repo\u2028line2"}}\n'
            )
            res_bad = cd.parse_codex_execution(
                raw_stdout=raw_incomplete, raw_stderr="", exit_code=0, summary_path=sp
            )
            self.assertFalse(res_bad["ok"])

            # With turn.completed -> U+2028 preserved intact and ok=True
            raw_complete = raw_incomplete + '{"type":"turn.completed"}\n'
            res_ok = cd.parse_codex_execution(
                raw_stdout=raw_complete, raw_stderr="", exit_code=0, summary_path=sp
            )
            self.assertTrue(res_ok["ok"])
            self.assertIn("\u2028", res_ok["summary"])


class TestGitBaselineAndEndToEndFakeCodex(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.state_dir = self.base / "state"
        self.fake_bin = self.base / "fake-codex"
        self.repo.mkdir()

        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.repo, check=True)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (self.repo / "dirty_before.txt").write_text("untouched pre-dirty\n", encoding="utf-8")
        subprocess.run(["git", "add", "src/app.py"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=self.repo, check=True)

        self.fake_bin.write_text(
            """#!/usr/bin/env python3
import json, os, pathlib, sys
argv = sys.argv[1:]
prompt = sys.stdin.read()
out_idx = argv.index("-o")
out_file = pathlib.Path(argv[out_idx + 1])
log_argv = pathlib.Path(os.environ["FAKE_CODEX_ARGV_LOG"])
log_argv.write_text(json.dumps({"argv": argv, "prompt": prompt, "cwd": str(pathlib.Path.cwd())}), encoding="utf-8")

is_resume = len(argv) >= 2 and argv[0] == "exec" and argv[1] == "resume"
sid = argv[-2] if is_resume else "11111111-2222-3333-4444-555555555555"
print(json.dumps({"type": "thread.started", "thread_id": sid}))

mode = os.environ.get("FAKE_CODEX_BEHAVIOR", "clean_edit")
if mode == "clean_edit":
    p = pathlib.Path.cwd() / "src" / "app.py"
    p.write_text("def add(a: int, b: int) -> int:\\n    return a + b\\n", encoding="utf-8")
    summary = "Updated src/app.py with type annotations and verified."
elif mode == "out_of_scope":
    (pathlib.Path.cwd() / "ROGUE.md").write_text("oops\\n", encoding="utf-8")
    summary = "Touched rogue file."
elif mode == "revert_rogue_and_edit":
    rogue = pathlib.Path.cwd() / "ROGUE.md"
    if rogue.exists():
        rogue.unlink()
    p = pathlib.Path.cwd() / "src" / "app.py"
    p.write_text("def add(a: int, b: int) -> int:\\n    return a + b\\n", encoding="utf-8")
    summary = "Removed ROGUE.md and updated src/app.py cleanly."
elif mode == "empty_summary":
    summary = ""
else:
    summary = "Read-only analysis complete."

if summary:
    out_file.write_text(summary, encoding="utf-8")
    print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": summary}}))
    print(json.dumps({"type": "turn.completed"}))
""",
            encoding="utf-8",
        )
        self.fake_bin.chmod(self.fake_bin.stat().st_mode | stat.S_IXUSR)
        self.argv_log = self.base / "argv.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _env(self, behavior: str) -> dict[str, str]:
        env = dict(os.environ)
        env["CODEX_DISPATCH_BIN"] = str(self.fake_bin)
        env["CODEX_DISPATCH_HOME"] = str(self.state_dir)
        env["FAKE_CODEX_ARGV_LOG"] = str(self.argv_log)
        env["FAKE_CODEX_BEHAVIOR"] = behavior
        return env

    def test_implement_and_resume_escalation(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "codex_dispatch.py"),
                "implement",
                "-C",
                str(self.repo),
                "--allow",
                "src/**",
                "--verify",
                "python3 -c 'import sys; sys.path.insert(0, \"src\"); import app; assert app.add(2, 3) == 5'",
                "--json",
            ],
            input="Add type hints to add().",
            text=True,
            capture_output=True,
            env=self._env("clean_edit"),
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        res = json.loads(proc.stdout)
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["touched_files"], ["src/app.py"])
        self.assertTrue(res["scope_ok"])
        self.assertTrue(res["verify"]["passed"])

        task_id = res["task_id"]
        proc_resume = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "codex_dispatch.py"), "resume", task_id, "--json"],
            input="Handle negative integers cleanly too.",
            text=True,
            capture_output=True,
            env=self._env("clean_edit"),
            check=False,
        )
        self.assertEqual(proc_resume.returncode, 0, msg=proc_resume.stderr)
        res2 = json.loads(proc_resume.stdout)
        self.assertTrue(res2["escalated"])
        self.assertEqual(res2["model"], "gpt-6.2-astra")
        self.assertEqual(res2["effort"], "high")

    def test_scope_violation_blocks_verify_from_running_and_clears_on_rework(self) -> None:
        marker = self.base / "verify_ran_marker"
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "codex_dispatch.py"),
                "implement",
                "-C",
                str(self.repo),
                "--allow",
                "src/**",
                "--verify",
                f"touch {marker}",
                "--json",
            ],
            input="Edit src only.",
            text=True,
            capture_output=True,
            env=self._env("out_of_scope"),
            check=False,
        )
        self.assertEqual(proc.returncode, 1)
        res = json.loads(proc.stdout)
        self.assertEqual(res["status"], "GATE_FAILED")
        self.assertFalse(res["scope_ok"])
        # Verify command MUST NOT have executed when scope gate failed!
        self.assertFalse(marker.exists())
        self.assertIsNone(res["verify"])

        proc_fix = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "codex_dispatch.py"), "resume", res["task_id"], "--json"],
            input="Delete ROGUE.md and only touch src/app.py.",
            text=True,
            capture_output=True,
            env=self._env("revert_rogue_and_edit"),
            check=False,
        )
        self.assertEqual(proc_fix.returncode, 0, msg=proc_fix.stderr + proc_fix.stdout)
        res_fixed = json.loads(proc_fix.stdout)
        self.assertEqual(res_fixed["status"], "OK")
        self.assertTrue(marker.exists())

    def test_managed_worktree_isolates_edits_and_runs_gates(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "codex_dispatch.py"),
                "implement",
                "-C",
                str(self.repo),
                "--worktree",
                "--allow",
                "src/**",
                "--verify",
                "grep -q 'int' src/app.py",
                "--json",
            ],
            input="Add type annotations inside isolated worktree.",
            text=True,
            capture_output=True,
            env=self._env("clean_edit"),
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
        res = json.loads(proc.stdout)
        self.assertEqual(res["status"], "OK")
        self.assertTrue(res["worktree"])
        self.assertEqual(res["touched_files"], ["src/app.py"])
        self.assertTrue(res["verify"]["passed"])
        # Main repo src/app.py remains untouched!
        self.assertNotIn("int", (self.repo / "src" / "app.py").read_text(encoding="utf-8"))

    def test_path_traversal_task_id_rejected_and_clean_preserves_foreign_dirs(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "codex_dispatch.py"), "resume", "../repo", "hi"],
            text=True,
            capture_output=True,
            env=self._env("clean_edit"),
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Invalid task_id", proc.stderr)

        foreign = self.state_dir / "other-tool-cache"
        foreign.mkdir(parents=True)
        (foreign / "keep.txt").write_text("do not delete", encoding="utf-8")
        os.utime(foreign, (1000, 1000))
        proc_clean = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "codex_dispatch.py"), "clean", "--days", "0"],
            text=True,
            capture_output=True,
            env=self._env("clean_edit"),
            check=False,
        )
        self.assertEqual(proc_clean.returncode, 0)
        self.assertTrue((foreign / "keep.txt").is_file())


if __name__ == "__main__":
    unittest.main()
