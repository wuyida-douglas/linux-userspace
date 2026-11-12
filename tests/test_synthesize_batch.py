from __future__ import annotations

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

from pipeline import supervise
from pipeline import synthesize_batch as sb


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class TargetResolutionTests(unittest.TestCase):
    def rows(self):
        return [
            {"task_id": "linux-001-cve-x-o-repo",
             "instance_id": "CVE-X::https://github.com/o/repo", "canonical_id": "CVE-X"},
            {"task_id": "linux-002-cve-y-o-other",
             "instance_id": "CVE-Y::https://github.com/o/other", "canonical_id": "CVE-Y"},
        ]

    def test_resolves_task_instance_canonical_and_display_names(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            write(results / "display-names.json", {
                "schema_version": 1,
                "mapping": {"linux-001-cve-x-o-repo": "cve-x-file-pov"}})
            tokens = ["linux-001-cve-x-o-repo",
                      "cve-y::https://github.com/o/other",
                      "cve-x-file-pov"]
            self.assertEqual(
                sb.resolve_targets(tokens, self.rows(), results),
                ["linux-001-cve-x-o-repo", "linux-002-cve-y-o-other"])

    def test_case_insensitive_fallback_and_unknown_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            self.assertEqual(
                sb.resolve_targets(["LINUX-002-CVE-Y-O-OTHER"], self.rows(), results),
                ["linux-002-cve-y-o-other"])
            with self.assertRaises(SystemExit):
                sb.resolve_targets(["linux-999-nope"], self.rows(), results)

    def test_ambiguous_canonical_id_is_rejected(self):
        rows = [
            {"task_id": "a", "instance_id": "CVE-X::one", "canonical_id": "CVE-X"},
            {"task_id": "b", "instance_id": "CVE-X::two", "canonical_id": "CVE-X"},
        ]
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(SystemExit):
            sb.resolve_targets(["CVE-X"], rows, Path(directory))


class WaveTests(unittest.TestCase):
    def test_waves_keep_order_and_last_partial(self):
        self.assertEqual(list(sb.waves(["a", "b", "c", "d", "e"], 2)),
                         [["a", "b"], ["c", "d"], ["e"]])

    def test_receipt_is_deterministic_and_matches_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            first = sb.receipt_for(results, ["a", "b"], 7)
            second = sb.receipt_for(results, ["a", "b"], 7)
            self.assertEqual(first, second)
            self.assertEqual(json.loads(first.read_text())["batch"], 7)
            self.assertEqual(json.loads(first.read_text())["fresh"], ["a", "b"])


class RoundTests(unittest.TestCase):
    def test_zero_wave_size_runs_one_continuous_batch(self):
        args = SimpleNamespace(wave_size=0, results=Path("/nonexistent"), force=True)
        with unittest.mock.patch.object(sb, "run_wave") as run:
            sb.run_round(args, ["a", "b", "c"], "initial", 1, None)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1], ["a", "b", "c"])

    def test_positive_wave_size_keeps_legacy_chunks(self):
        args = SimpleNamespace(wave_size=2, results=Path("/nonexistent"), force=True)
        with unittest.mock.patch.object(sb, "run_wave") as run:
            sb.run_round(args, ["a", "b", "c"], "initial", 1, None)
        self.assertEqual([call.args[1] for call in run.call_args_list],
                         [["a", "b"], ["c"]])

    def test_batch_count(self):
        self.assertEqual(sb.batch_count([], 0), 0)
        self.assertEqual(sb.batch_count(["a", "b", "c"], 0), 1)
        self.assertEqual(sb.batch_count(["a", "b", "c"], 2), 2)
        self.assertEqual(sb.batch_count(["a", "b", "c"], 40), 1)


class RetryTests(unittest.TestCase):
    def make(self, root: Path, task: str, status: str, *, manifest=True,
             failure_class=None):
        if manifest:
            (root / "sample/tasks" / task / "input").mkdir(parents=True, exist_ok=True)
            (root / "sample/tasks" / task / "input/manifest.json").write_text("{}")
        write(root / "results" / task / "result.json",
              {"status": status, "failure_class": failure_class})

    def test_only_retryable_failures_with_usable_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make(root, "ok", "failed")
            self.make(root, "missing-input", "failed", manifest=False)
            self.make(root, "unavailable", "failed", failure_class="input_unavailable")
            self.make(root, "passed", "passed")
            self.make(root, "pipeline-error", "error")
            self.assertEqual(
                sb.retryable_failures(root / "sample", root / "results",
                                      ["ok", "missing-input", "unavailable", "passed",
                                       "pipeline-error"]),
                ["ok", "pipeline-error"])

    def test_archive_moves_evidence_and_clears_supervisor_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample"
            results = root / "results"
            self.make(root, "failed", "failed")
            self.make(root, "passed", "passed")
            (results / "failed/workspace/delivery").mkdir(parents=True)
            (results / "failed/workspace/delivery/task.json").write_text("{}")
            write(results / "supervisor-state.json", {
                "schema_version": 1,
                "children": {"failed": {"pid": None, "retry_blocked": "x"},
                             "passed": {"pid": None}},
                "scheduled": ["failed", "passed"],
                "final_tasks": ["failed"],
                "initial_launches": {"failed": {"batch": 1}},
                "batch_members": ["failed", "passed"],
            })
            archived = sb.archive_failed_tasks(sample, results, ["failed", "passed"])
            self.assertEqual(archived, ["failed"])
            self.assertFalse((results / "failed").exists())
            saved = list((results / ".attempts/failed").glob("*/result.json"))
            self.assertEqual(len(saved), 1)
            self.assertTrue((saved[0].parent / "workspace/delivery/task.json").is_file())
            state = json.loads((results / "supervisor-state.json").read_text())
            self.assertNotIn("failed", state["children"])
            self.assertNotIn("failed", state["scheduled"])
            self.assertNotIn("failed", state["final_tasks"])
            self.assertNotIn("failed", state["initial_launches"])
            self.assertNotIn("failed", state["batch_members"])
            self.assertIn("passed", state["children"])


class SupervisorLaunchTests(unittest.TestCase):
    def test_launch_passes_env_file_to_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with unittest.mock.patch.object(sb.subprocess, "Popen") as popen:
                supervise.launch("task", root / "sample", root / "results",
                                 400, 18000, env_file=root / "env")
            command = popen.call_args.args[0]
            self.assertEqual(command[command.index("--env-file") + 1], str(root / "env"))


class CommandTests(unittest.TestCase):
    def test_wave_command_passes_env_file_and_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = SimpleNamespace(
                sample=root / "sample", results=root / "results",
                env_file=root / "env", concurrency=4, max_turns=400,
                timeout=18000, review_turns=140, review_timeout=5400,
                verify_timeout=1800)
            (root / "env").write_text("")
            with unittest.mock.patch.object(
                    sb.subprocess, "run",
                    return_value=SimpleNamespace(returncode=0)) as run:
                sb.run_wave(args, ["a", "b"], 1, 7, None, label="initial")
            command = run.call_args.args[0]
            self.assertIn("--env-file", command)
            self.assertEqual(command[command.index("--env-file") + 1], str(root / "env"))
            self.assertEqual(command[command.index("--batch-number") + 1], "7")
            self.assertEqual(command[command.index("--batch-size") + 1], "2")
            self.assertEqual(command[command.index("--only") + 1:command.index("--only") + 3],
                             ["a", "b"])


if __name__ == "__main__":
    unittest.main()