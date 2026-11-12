from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from pipeline import synthesis_status as status


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class ScanTests(unittest.TestCase):
    def test_scan_separates_roles_and_result_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            proc = root / "proc"
            commands = {
                100: (["python", "-m", "pipeline.synthesize_batch",
                       "--results", str(results)], 1),
                101: (["python", "-m", "pipeline.supervise",
                       "--results", str(results)], 1),
                102: (["python", "-m", "pipeline.run",
                       "--results", str(results), "--only", "task-a"], 1),
                103: (["python", "-m", "pipeline.run",
                       "--results", str(root / "other"), "--only", "task-b"], 1),
                # harbor.py's multiprocessing fork inherits the worker cmdline.
                104: (["python", "-m", "pipeline.run",
                       "--results", str(results), "--only", "task-a"], 102),
            }
            for pid, (argv, ppid) in commands.items():
                (proc / str(pid)).mkdir(parents=True)
                (proc / str(pid) / "cmdline").write_bytes(
                    b"\0".join(part.encode() for part in argv) + b"\0")
                (proc / str(pid) / "stat").write_text(
                    f"{pid} (python) S {ppid} 1 1 0 -1 0")
            coordinators, supervisors, workers = status.scan(results, proc)
            self.assertEqual(coordinators, [100])
            self.assertEqual(supervisors, [101])
            self.assertEqual(workers, {"task-a": [102]})


class MainTests(unittest.TestCase):
    def test_stage_counts_and_live_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample"
            results = root / "results"
            rows = [
                {"task_id": "a", "instance_id": "CVE-a", "canonical_id": "CVE-a"},
                {"task_id": "b", "instance_id": "CVE-b", "canonical_id": "CVE-b"},
                {"task_id": "c", "instance_id": "CVE-c", "canonical_id": "CVE-c"},
            ]
            sample.mkdir()
            (sample / "selection.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows))
            write(results / "a/result.json", {"status": "routing"})
            write(results / "b/result.json", {"status": "synthesizing"})
            buffer = io.StringIO()
            with unittest.mock.patch.object(
                    status, "scan",
                    return_value=([100], [101], {"a": [200], "b": [201, 202]})), \
                    unittest.mock.patch("sys.argv", [
                        "synthesis_status", "--sample", str(sample),
                        "--results", str(results)]), \
                    contextlib.redirect_stdout(buffer):
                self.assertEqual(status.main(), 0)
            text = buffer.getvalue()
            self.assertIn("coordinator: running pid=100", text)
            self.assertIn("supervisor:  running pid=101", text)
            self.assertIn("workers:     3 process(es) for 2 target task(s)", text)
            self.assertIn("routing", text)
            self.assertIn("synthesizing", text)
            self.assertIn("missing", text)
            self.assertIn("target=3 terminal=0 remaining=3 live_tasks=2 stale=0", text)


if __name__ == "__main__":
    unittest.main()