from __future__ import annotations

import shutil
import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

# This suite asserts the supervisor's pre-rename task paths. Production keeps
# automatic canonical+branch renaming enabled.
os.environ.setdefault("PIPELINE_DISABLE_RESULT_RENAME", "1")

from pipeline import supervise
from pipeline.supervise import pipeline_worker_command, worker_start_error


class WorkerIdentityTests(unittest.TestCase):
    def test_absolute_venv_executable_is_a_real_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "1063472").mkdir()
            (proc / "1063472/cmdline").write_bytes(
                b"/nvme/wuyida/.venv/bin/python\0-m\0pipeline.run\0--only\0linux-001\0")
            (proc / "1063472/stat").write_text("1063472 (python) S 1 1 1 0 -1 4194560")
            self.assertEqual(pipeline_worker_command(1063472, proc)[:3],
                             ["/nvme/wuyida/.venv/bin/python", "-m", "pipeline.run"])

    def test_nested_only_child_does_not_own_the_task_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            for pid in (100, 101):
                (proc / str(pid)).mkdir()
            (proc / "100/cmdline").write_bytes(b"python\0-m\0pipeline.run\0--only\0linux-001\0")
            (proc / "100/stat").write_text("100 (python) S 1 1 1 0 -1 4194560")
            (proc / "101/cmdline").write_bytes(b"python\0-m\0pipeline.run\0--only\0linux-001\0")
            (proc / "101/stat").write_text("101 (python) S 100 1 1 0 -1 4194560")
            self.assertIsNone(pipeline_worker_command(101, proc))

    def test_supervisor_option_text_is_not_a_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "100").mkdir()
            (proc / "100/cmdline").write_bytes(
                b"python\0-m\0pipeline.supervise\0--only\0linux-001\0")
            (proc / "100/stat").write_text("100 (python) S 1 1 1 0 -1 4194560")
            self.assertIsNone(pipeline_worker_command(100, proc))


class WorkerStartTests(unittest.TestCase):
    def test_import_failure_after_latest_launch_is_recoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "supervisor.log").write_text(
                '[2026-11-07T16:27:02Z] launch: python -m pipeline.run --resume\n'
                'Traceback (most recent call last):\n'
                '  File "pipeline/run.py", line 20, in <module>\n'
                "ModuleNotFoundError: No module named 'pipeline.common'\n", encoding="utf-8")
            self.assertEqual(worker_start_error(task), "ModuleNotFoundError: No module named 'pipeline.common'")

    def test_previous_traceback_does_not_mask_later_worker_output(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "supervisor.log").write_text(
                '[2026-11-07T16:27:02Z] launch: python -m pipeline.run --resume\n'
                'Traceback (most recent call last):\n'
                "ModuleNotFoundError: No module named 'pipeline.common'\n"
                '[2026-11-07T16:31:00Z] launch: python -m pipeline.run --resume\n'
                'linux-004: failed\n', encoding="utf-8")
            self.assertIsNone(worker_start_error(task))

    def test_runtime_task_exception_is_not_an_import_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            (task / "supervisor.log").write_text(
                '[2026-11-07T16:27:02Z] launch: python -m pipeline.run\n'
                'Traceback (most recent call last):\n'
                'ValueError: invalid route\n', encoding="utf-8")
            self.assertIsNone(worker_start_error(task))


class SelectionReceiptTests(unittest.TestCase):
    def test_observed_duplicate_never_recovers_and_fresh_task_still_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "selection.jsonl").write_text(
                '{"task_id": "duplicate", "instance_id": "CVE-d::project"}\n'
                '{"task_id": "fresh", "instance_id": "CVE-f::project"}\n')
            (root / "duplicate").mkdir()
            (root / "duplicate/result.json").write_text('{"status": "rejected"}')
            receipt = root / "batch-selection.json"
            receipt.write_text(json.dumps({"batch": 2, "fresh": ["fresh"], "carried": [],
                                           "observed_only": ["duplicate"]}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--batch-selection", str(receipt),
                                                       "--batch-number", "2",
                                                       "--only", "fresh", "duplicate", "--once"]):
                launch.return_value.pid = 4321
                self.assertEqual(supervise.main(), 0)
            self.assertEqual(launch.call_args.args[0], "fresh")
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["children"]["duplicate"]["observation_final_status"], "rejected")
            self.assertEqual(state["batch_members"], ["fresh"])
            self.assertEqual(state["batch_number"], 2)

    def test_receipt_preserves_positions_of_unavailable_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "selection.jsonl").write_text(
                '{"task_id": "complete", "instance_id": "CVE-a::project"}\n'
                '{"task_id": "missing", "instance_id": "CVE-b::project"}\n'
                '{"task_id": "third", "instance_id": "CVE-c::project"}\n')
            (root / "tasks/complete/input").mkdir(parents=True)
            (root / "tasks/complete/input/manifest.json").write_text("{}")
            (root / "download-report.json").write_text(json.dumps({"tasks": [
                {"task_id": "complete", "status": "complete"},
                {"task_id": "missing", "status": "error", "error": "S3 unavailable"},
                {"task_id": "third", "status": "complete"}]}))
            receipt = root / "batch-selection.json"
            receipt.write_text(json.dumps({"batch": 1, "fresh": ["complete", "missing"],
                                           "carried": [], "observed_only": []}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--batch-selection", str(receipt),
                                                       "--batch-number", "1", "--only", "complete", "missing", "--once"]):
                launch.return_value.pid = 4321
                self.assertEqual(supervise.main(), 0)
            self.assertEqual(launch.call_args.args[0], "complete")
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["batch_members"], ["complete", "missing"])

    def test_receipt_cannot_expand_an_ordinary_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "selection.jsonl").write_text("")
            (root / "batch-selection.json").write_text(json.dumps({
                "batch": 2, "fresh": [str(index) for index in range(31)],
                "carried": [], "observed_only": []}))
            with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                   "--results", str(root),
                                                   "--batch-selection", str(root / "batch-selection.json")]), \
                    self.assertRaises(SystemExit):
                supervise.main()


class CarriedRecoveryTests(unittest.TestCase):
    def test_copied_recovery_preserves_source_and_uses_same_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "old/task"
            source.joinpath("workspace/delivery").mkdir(parents=True)
            source.joinpath("workspace/route.json").write_text(
                '{"instance_id": "CVE-test::project"}')
            source.joinpath("synthesis").mkdir()
            source.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            source.joinpath("result.json").write_text(
                '{"status": "error", "failure_class": "pipeline"}')
            target = root / "new"
            self.assertEqual(supervise.carry_workspaces([source], target, {"task"}), {"task"})
            (target / "task/result.json").write_text('{"status": "reviewing"}')
            self.assertEqual(json.loads((source / "result.json").read_text())["status"], "error")
            self.assertTrue((target / "task/carry-provenance.json").is_file())
            with self.assertRaises(ValueError):
                supervise.carry_workspaces([source], target, {"task"})


    def test_carried_incomplete_result_recovers_route_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "old/task"
            source.joinpath("workspace").mkdir(parents=True)
            source.joinpath("workspace/route.json").write_text(
                '{"instance_id": "CVE-test::project"}')
            source.joinpath("workspace/delivery").mkdir()
            source.joinpath("workspace/review.json").write_text('{"passed": true}')
            source.joinpath("synthesis").mkdir()
            source.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            source.joinpath("result.json").write_text(
                '{"status": "error", "failure_class": "pipeline"}')
            target = root / "new"
            supervise.carry_workspaces([source], target, {"task"}, {"task": {
                "schema_version": 1, "task_id": "task",
                "instance_id": "CVE-test::project", "mode": "review"}})
            copied_result = json.loads((target / "task/result.json").read_text())
            self.assertEqual(copied_result["instance_id"], "CVE-test::project")
            original_result = json.loads((source / "result.json").read_text())
            self.assertNotIn("instance_id", original_result)
            provenance = json.loads(
                (target / "task/carry-provenance.json").read_text())
            self.assertEqual(provenance["instance_id"], "CVE-test::project")
            self.assertTrue(provenance["same_instance_continuation"])

    def test_rejected_review_is_terminal_and_preserves_repair_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-014"
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("workspace/input/src").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text("{}")
            base.joinpath("workspace/repair-request.json").write_text('{"reason": "stale metadata only"}')
            base.joinpath("workspace/review.json").write_text(json.dumps({
                "passed": False,
                "evidence": "oracle rejects a valid alternative exploit: private marker mismatch"}))
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            base.joinpath("result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "review_rejected"}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--concurrency", "30",
                                                       "--batch-size", "30", "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            request = json.loads(base.joinpath("workspace/repair-request.json").read_text())
            self.assertEqual(request["reason"], "stale metadata only")
            self.assertFalse(json.loads(base.joinpath("workspace/review.json").read_text())["passed"])


class StrictProtocolEvidenceTests(unittest.TestCase):
    def test_published_task_directory_is_acceptance_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "cve-2024-0001-file-pov/harbor-runtime-profile"
            profile.mkdir(parents=True)
            (root / "cve-2024-0001-file-pov/image-lock.json").write_text("{}")
            (profile / "task.toml").write_text("")
            row = {"export_task_id": "cve-2024-0001-file-pov"}
            self.assertEqual(supervise.published_task_path(row, "linux-001", root),
                             root / "cve-2024-0001-file-pov")
            self.assertIsNone(supervise.published_task_path({}, "linux-002", root))

    def test_strict_acceptance_requires_two_harbor_agent_runs(self):
        row = {"status": "passed", "review": {"passed": True}, "harbor": {
            "status": "passed",
            "acceptance_runs": [{"reward": 1.0}, {"reward": 1.0}]}}
        self.assertTrue(supervise.strictly_accepted(row))
        row["harbor"]["acceptance_runs"][1]["reward"] = 0.0
        self.assertFalse(supervise.strictly_accepted(row))
        row["harbor"]["acceptance_runs"] = [{"reward": 1.0}]
        self.assertFalse(supervise.strictly_accepted(row))

    def test_strict_acceptance_uses_oracle_and_fixed_evidence(self):
        row = {"status": "passed", "review": {"passed": True}, "harbor": {
            "gold": {"reward": 1.0}, "null": {"reward": 0.0},
            "differential_from_final_bundle": {"status": "passed", "report": {
                "success": True,
                "vulnerable": {"triggered": True, "health": {"returncode": 0},
                               "submission_result": {"returncode": 134}},
                "fixed": {"triggered": False, "solution": {"returncode": 0},
                          "patched_health": {"returncode": 0},
                          "submission_result": {"returncode": 1}}}}}}
        self.assertTrue(supervise.strictly_accepted(row))
        row["harbor"]["differential_from_final_bundle"]["report"]["vulnerable"]["triggered"] = False
        self.assertFalse(supervise.strictly_accepted(row))


class HistoricalGoldDefectTests(unittest.TestCase):
    def test_readonly_gold_history_invalidates_current_pass_and_resumes_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-012"
            base = root / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text("{}")
            base.joinpath("workspace/review.json").write_text('{"passed": true}')
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            old = {"status": "infra_error",
                   "vulnerable": {"oracle": {"returncode": 1},
                                  "submission_result": {"output": "Read-only file system"}},
                   "fixed": {"oracle": {"returncode": 0},
                             "submission_result": {"output": "Read-only file system"}}}
            evidence = base.joinpath("infrastructure-attempts/old")
            evidence.mkdir(parents=True)
            (evidence / "result.json").write_text(json.dumps({"harbor": {
                "gold": {"reward": 0.0}, "differential_from_final_bundle": {"report": old}}}))
            row = {"status": "passed", "review": {"passed": True}, "harbor": {
                "gold": {"reward": 1.0}, "null": {"reward": 0.0},
                "differential_from_final_bundle": {"status": "passed", "report": {
                    "success": True, "vulnerable": {"submission_result": {"returncode": 0}},
                    "fixed": {"submission_result": {"returncode": 0}}}}}}
            (base / "result.json").write_text(json.dumps(row))
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"review_retry_count": 1}}, "scheduled": [task]}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                launch.return_value.pid = 4321
                self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            self.assertTrue((base / "workspace/review.json").is_file())
            self.assertFalse((base / "workspace/repair-request.json").exists())


class ReviewRetryBoundTests(unittest.TestCase):
    def test_terminal_review_delivery_error_does_not_start_an_endless_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-004"
            base = root / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text("{}")
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            base.joinpath("result.json").write_text(json.dumps({
                "status": "error", "failure_class": "pipeline",
                "error": "ValueError: FILE routes require host_type=null"}))
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "OSV-test::project"}) + "\n")
            (root / "supervisor-state.json").write_text(json.dumps({
                "schema_version": 1, "children": {task: {
                    "retry_reason": "review_incomplete", "final_status": "error",
                    "review_incomplete_retry_count": 1, "review_launched": True,
                    "retry_blocked": "review_attempt_completed"}}, "scheduled": [task]}))
            process_scan = unittest.mock.Mock(stdout="", returncode=0)
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch.object(supervise.subprocess, "run", return_value=process_scan):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--concurrency", "30",
                                                       "--batch-size", "30", "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["children"][task]["retry_blocked"], "review_attempt_completed", state)

    def test_completed_review_attempt_cannot_relaunch_without_new_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-004"
            base = root / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text("{}")
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            base.joinpath("result.json").write_text(json.dumps({
                "status": "error", "failure_class": "pipeline",
                "error": "reviewer process failed before writing a verdict"}))
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "OSV-test::project"}) + "\n")
            (root / "supervisor-state.json").write_text(json.dumps({
                "schema_version": 1, "children": {task: {
                    "retry_reason": "review_incomplete", "final_status": "error",
                    "review_incomplete_retry_count": 0, "review_launched": True}},
                "scheduled": [task]}))
            process_scan = unittest.mock.Mock(stdout="", returncode=0)
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch.object(supervise.subprocess, "run", return_value=process_scan):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--concurrency", "30",
                                                       "--batch-size", "30", "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["children"][task]["retry_blocked"], "review_attempt_completed", state)

    def test_legacy_handoff_marker_cannot_relaunch_a_terminal_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-032"
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text("{}")
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            base.joinpath("result.json").write_text(json.dumps({
                "status": "error", "failure_class": "pipeline",
                "error": "ValueError: missing delivery/instruction.md"}))
            (root / "supervisor-state.json").write_text(json.dumps({
                "schema_version": 1, "children": {task: {
                    "retry_reason": "review_incomplete", "final_status": "error",
                    "review_incomplete_retry_count": 0, "review_launched": True}},
                "scheduled": [task]}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch.object(supervise.subprocess, "run",
                                               return_value=unittest.mock.Mock(stdout="", returncode=0)):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["children"][task]["retry_blocked"],
                             "review_attempt_completed")


class AutoRetryFailedTests(unittest.TestCase):
    def test_failed_harbor_task_is_not_requeued_automatically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-050"
            base = root / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text("{}")
            base.joinpath("workspace/review.json").write_text('{"passed": true}')
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            base.joinpath("result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 1.0}, "null": {"reward": 0.0},
                           "differential_from_final_bundle": {
                               "status": "error", "report": {"status": "infra_error"}}},
            }))
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            (root / "supervisor-state.json").write_text(json.dumps({
                "schema_version": 1, "children": {}, "scheduled": []}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch.object(supervise.subprocess, "run",
                                               return_value=unittest.mock.Mock(stdout="", returncode=0)):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["children"][task]["retry_blocked"], "auto_retry_disabled", state)


class SharedRecoveryAdoptionTests(unittest.TestCase):
    def test_terminal_adopted_review_rejection_requires_manual_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample, results, recovery = root / "sample", root / "results", root / "old"
            sample.mkdir()
            (sample / "selection.jsonl").write_text(json.dumps({
                "task_id": "linux-001", "instance_id": "CVE-test::project"}) + "\n")
            task = "linux-017-old"
            base = recovery / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text(json.dumps({
                "instance_id": "CVE-test::old", "accepted": True}))
            base.joinpath("workspace/review.json").write_text(json.dumps({
                "passed": False,
                "evidence": "provenance record is false: wrong input description"}))
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            base.joinpath("result.json").write_text(json.dumps({
                "task_id": task, "instance_id": "CVE-test::old",
                "status": "failed", "failure_class": "review_rejected"}))
            results.mkdir()
            (recovery / "supervisor-state.json").write_text(json.dumps({"sample": str(sample)}))
            (results / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "external_worker": True,
                                    "worker_results": str(recovery), "recovery_merged": True,
                                    "recovery_merged_at": (base / "result.json").stat().st_mtime_ns}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(sample),
                                                       "--results", str(results), "--recovery-results", str(recovery),
                                                       "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            self.assertTrue(base.joinpath("workspace/review.json").is_file())
            self.assertFalse(base.joinpath("workspace/repair-request.json").exists())

    def test_terminal_adopted_gold_exit_defect_does_not_resume_synthesis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample, results, recovery = root / "sample", root / "results", root / "old"
            task = "linux-017-old"
            sample.mkdir()
            (sample / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "CVE-test::old"}) + "\n")
            base = recovery / task
            base.joinpath("workspace/delivery").mkdir(parents=True)
            base.joinpath("harbor").mkdir()
            base.joinpath("workspace/route.json").write_text('{"instance_id": "CVE-test::old"}')
            base.joinpath("workspace/review.json").write_text('{"passed": true}')
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            base.joinpath("result.json").write_text(json.dumps({
                "instance_id": "CVE-test::old",
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 0.0}, "differential_from_final_bundle": {
                    "report": {"status": "infra_error", "vulnerable": {"oracle": {"returncode": 0}},
                               "fixed": {"error_stage": "submission", "submission_result": {
                                   "returncode": 1, "output": "fixed disclosure absent"}}}}}}))
            results.mkdir()
            (recovery / "supervisor-state.json").write_text(json.dumps({"sample": str(sample)}))
            (results / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "external_worker": True,
                                    "worker_results": str(recovery), "recovery_merged": True,
                                    "retry_reason": "review_infrastructure",
                                    "acceptance_resume_requested": True,
                                    "recovery_merged_at": (base / "result.json").stat().st_mtime_ns}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "worker_alive", return_value=False), \
                    unittest.mock.patch.object(supervise.subprocess, "run",
                                               return_value=unittest.mock.Mock(stdout="", returncode=0)):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(sample),
                                                       "--results", str(results), "--recovery-results", str(recovery),
                                                       "--only", "linux-001", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            self.assertTrue(base.joinpath("workspace/review.json").is_file())
            self.assertTrue(base.joinpath("harbor").is_dir())
            self.assertFalse(base.joinpath("workspace/repair-request.json").exists())


class ExplicitCarryPlanTests(unittest.TestCase):
    def route_only_source(self, root: Path) -> Path:
        source = root / "old/task"
        source.joinpath("workspace/input/src").mkdir(parents=True)
        source.joinpath("route").mkdir()
        source.joinpath("route/trajectory.jsonl").write_text('{"turn": 45}\n')
        source.joinpath("result.json").write_text(json.dumps({
            "task_id": "task", "instance_id": "CVE-test::project",
            "status": "error", "failure_class": "pipeline",
            "error": "RuntimeError: routing agent did not complete: max_turns"}))
        return source

    def route_handoff_plan(self) -> dict:
        return {"schema_version": 1, "task_id": "task", "instance_id": "CVE-test::project",
                "mode": "route", "reason": "route_budget",
                "trajectory": "route/trajectory.jsonl"}

    def test_route_only_carry_preserves_source_and_copies_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.route_only_source(root)
            original = (source / "result.json").read_text()
            carried = supervise.carry_workspaces([source], root / "new", {"task"},
                                                 {"task": self.route_handoff_plan()})
            self.assertEqual(carried, {"task"})
            self.assertEqual((source / "result.json").read_text(), original)
            self.assertTrue((source / "route/trajectory.jsonl").is_file())
            self.assertTrue((root / "new/task/route/trajectory.jsonl").is_file())

    def test_route_only_carry_cannot_invent_a_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.route_only_source(root)
            with self.assertRaisesRegex(ValueError, "frozen route"):
                supervise.carry_workspaces([source], root / "new", {"task"})

    def test_synthesis_carry_copies_route_and_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.route_only_source(root)
            source.joinpath("workspace/route.json").write_text("{}")
            carried = supervise.carry_workspaces([source], root / "new", {"task"}, {"task": {
                "schema_version": 1, "task_id": "task",
                "instance_id": "CVE-test::project", "mode": "synthesis"}})
            self.assertEqual(carried, {"task"})
            self.assertTrue((root / "new/task/workspace/route.json").is_file())
            self.assertTrue((root / "new/task/workspace/input/src").is_dir())

    def test_launch_passes_carried_route_and_synthesis_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            workspace = results / "task/workspace"
            with unittest.mock.patch.object(supervise.subprocess, "Popen") as popen:
                popen.return_value.pid = 123
                supervise.launch("task", Path("/sample"), results, 1, 1,
                                 continue_synthesis=True, workspace_from=workspace,
                                 concurrency=40)
                argv = popen.call_args.args[0]
                self.assertIn("--continue-synthesis", argv)
                self.assertIn(str(workspace), argv)
                self.assertIn("40", argv)
            with unittest.mock.patch.object(supervise.subprocess, "Popen") as popen:
                popen.return_value.pid = 123
                supervise.launch("task", Path("/sample"), results, 1, 1,
                                 route_from=results / "task/workspace/route.json")
                self.assertIn("--route-from", popen.call_args.args[0])
            with unittest.mock.patch.object(supervise.subprocess, "Popen") as popen:
                popen.return_value.pid = 123
                supervise.launch("task", Path("/sample"), results, 1, 1,
                                 route_handoff=results / "task/route/trajectory.jsonl")
                self.assertIn("--route-handoff-from", popen.call_args.args[0])

    def test_carry_without_explicit_plan_never_launches_an_empty_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            task.joinpath("workspace/input/src").mkdir(parents=True)
            task.joinpath("workspace/route.json").write_text("{}")
            task.joinpath("workspace/delivery").mkdir()
            task.joinpath("synthesis").mkdir()
            task.joinpath("synthesis/result.json").write_text('{"status": "completed"}')
            task.joinpath("carry-provenance.json").write_text(json.dumps({
                "same_instance_continuation": True, "instance_id": "CVE-test::project"}))
            task.joinpath("result.json").write_text(json.dumps({
                "task_id": "task", "instance_id": "CVE-test::project",
                "status": "error", "failure_class": "pipeline",
                "error": "reviewer interrupted before review.json"}))
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": "task", "instance_id": "CVE-test::project"}) + "\n")
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {"task": {"carried_recovery": True}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", "task", "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertFalse(launch.called)
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["children"]["task"]["carry_blocked"], "missing_explicit_recovery_plan")


class BoundedRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Production defaults to "failures are terminal"; these tests exercise
        # the bounded recovery paths themselves, so they opt back in.
        patcher = unittest.mock.patch.object(supervise, "FAILURES_TERMINAL", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_abandoned_review_recovery_is_not_terminal_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-004"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/input/src").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "review").mkdir()
            (base / "review/trajectory.jsonl").write_text('{"turn": 100}\n')
            (base / "review/result.json").write_text('{"status": "max_turns"}')
            (base / "result.json").write_text(json.dumps({"status": "reviewing"}))
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            state_path = root / "supervisor-state.json"
            state_path.write_text(json.dumps({
                "children": {task: {
                    "pid": None, "recovery_requested": True,
                    "last_status": "reviewing", "review_incomplete_retry_count": 0,
                    "retry_reason": "review_infrastructure",
                }},
            }))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                import sys
                old_argv = sys.argv
                sys.argv = ["supervise", "--sample", str(root), "--results", str(root),
                            "--only", task, "--once"]
                try:
                    self.assertEqual(supervise.main(), 0)
                finally:
                    sys.argv = old_argv
            self.assertTrue(launch.called)
            self.assertFalse(launch.call_args.kwargs["resume_harbor"])
            self.assertTrue(launch.call_args.kwargs["review_delivery"])
            self.assertEqual(launch.call_args.args[4], 18000)
            self.assertEqual(launch.call_args.args[2], root)
            self.assertTrue((base / "retry-evidence/review-incomplete/trajectory.jsonl").is_file())

    def test_launched_bounded_recovery_cannot_restart_from_stale_interrupted_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-002"
            base = root / task
            base.joinpath("workspace/input/src").mkdir(parents=True)
            base.joinpath("workspace/route.json").write_text("{}")
            base.joinpath("synthesis").mkdir()
            base.joinpath("synthesis/result.json").write_text('{"status": "max_turns"}')
            base.joinpath("result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed"}))
            (root / "selection.jsonl").write_text(json.dumps({
                "task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "recovery_requested": True,
                                    "retry_reason": "bounded_recovery",
                                    "bounded_recovery_launched": True, "final_status": "failed"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "worker_alive", return_value=False), \
                    unittest.mock.patch.object(supervise.subprocess, "run",
                                               return_value=unittest.mock.Mock(stdout="", returncode=0)):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            state = json.loads((root / "supervisor-state.json").read_text())
            self.assertEqual(state["children"][task]["retry_reason"],
                             "manual_recovery_required")

    def test_explicit_delivery_repair_is_preserved_without_relaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-017"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/input/src").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/repair-request.json").write_text('{"reason": "delivery_contract_repair"}')
            (base / "result.json").write_text(json.dumps({
                "status": "error", "failure_class": "pipeline",
                "error": "ValueError: sidecar_services must contain service names"}))
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--concurrency", "30",
                                                       "--batch-size", "30", "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            self.assertTrue((base / "workspace/repair-request.json").is_file())
            self.assertEqual(json.loads((base / "result.json").read_text())["error"],
                             "ValueError: sidecar_services must contain service names")

    def test_legacy_complete_workspace_error_does_not_resume_synthesis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-003"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/input/src").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "review").mkdir()
            (base / "review/result.json").write_text('{"status": "completed"}')
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "route": {"accepted": True},
                "error": "continue-synthesis needs route or existing workspace"}))
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 0,
                                    "review_incomplete_retry_count": 1,
                                    "retry_reason": "review_incomplete"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            self.assertTrue((base / "workspace/route.json").is_file())
            self.assertEqual(json.loads((base / "result.json").read_text())["error"],
                             "continue-synthesis needs route or existing workspace")

    def test_approved_complete_delivery_never_resumes_synthesis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-003"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/input/src").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "result.json").write_text(json.dumps({
                "status": "error", "route": {"accepted": True},
                "error": "ValueError: completed delivery requires --resume; refusing to replace it with a fresh route"}))
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 0,
                                    "retry_reason": "completed_route_recovery"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertTrue(launch.call_args.kwargs["resume_harbor"])
            self.assertFalse(launch.call_args.kwargs["review_delivery"])
            self.assertEqual(launch.call_args.args[4], 18000)

    def test_failures_terminal_mode_never_relaunches_an_errored_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-003"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "result.json").write_text(json.dumps({
                "status": "error", "failure_class": "pipeline",
                "error": "RuntimeError: Harbor trial failed"}))
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 0,
                                    "retry_reason": "review_infrastructure"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None), \
                    unittest.mock.patch.object(supervise, "FAILURES_TERMINAL", True):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()

    def test_approved_delivery_without_result_resumes_harbor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-003"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 0,
                                    "retry_reason": "completed_route_recovery"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertTrue(launch.call_args.kwargs["resume_harbor"])
            self.assertFalse(launch.call_args.kwargs["review_delivery"])
            self.assertEqual(launch.call_args.args[4], 18000)

    def test_approved_delivery_with_archived_gold_failure_retries_harbor_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-007"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/input/src").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "review").mkdir()
            (base / "review/result.json").write_text('{"status": "completed"}')
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed"}))
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (base / "retry-evidence/harbor-gold-runner-scratch").mkdir(parents=True)
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 1,
                                    "review_retry_count": 1,
                                    "retry_reason": "review_infrastructure"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertTrue(launch.call_args.kwargs["resume_harbor"])
            self.assertFalse(launch.call_args.kwargs["review_delivery"])
            self.assertEqual(launch.call_args.args[4], 18000)

    def test_file_pov_gold_crash_protocol_error_retries_current_verifier_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-016"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 0.0},
                           "differential_from_final_bundle": {
                               "status": "passed", "report": {"success": True}}}}))
            evidence = base / "harbor/jobs/task-gold/trial/verifier"
            evidence.mkdir(parents=True)
            (evidence / "evidence.json").write_text(json.dumps({
                "branch": "FILE-POV", "status": "infra_error",
                "vulnerable": {"error_stage": "submission",
                               "error": "submission must exit 0 after the protocol exchange",
                               "submission_result": {"returncode": 134}}}))
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 1,
                                    "retry_reason": "review_infrastructure"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertTrue(launch.call_args.kwargs["resume_harbor"])
            self.assertEqual(launch.call_args.args[4], 18000)
            self.assertFalse((base / "harbor").exists())
            self.assertTrue((base / "retry-evidence/harbor-file-pov-gold-protocol").is_dir())

    def test_final_differential_does_not_admit_unproven_gold_delivery_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-003"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 0.0},
                           "differential_from_final_bundle": {
                               "status": "passed", "report": {
                                   "status": "this_bug",
                                   "vulnerable": {"oracle": {"returncode": 1}},
                                   "fixed": {"oracle": {"returncode": 0}}}}}}))
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "delivery_retry_count": 0}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertFalse(launch.called)
            self.assertFalse((base / "workspace/repair-request.json").exists())

    def test_readonly_log_does_not_admit_delivery_repair_without_oracle_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-017"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            output = "[*] target disclosed account\n[!] copy failed: Permission denied"
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 0.0}, "differential_from_final_bundle": {
                    "status": "failed", "report": {"status": "this_bug",
                        "vulnerable": {"oracle": {"returncode": 0}},
                        "fixed": {"oracle": {"returncode": 1},
                                  "submission_result": {"returncode": 1, "output": output}}}}}}))
            evidence = base / "harbor/jobs/task-gold/trial/verifier"
            evidence.mkdir(parents=True)
            (evidence / "evidence.json").write_text(json.dumps({
                "vulnerable": {"triggered": True, "submission_result": {"returncode": 0, "output": output}}}))
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "delivery_retry_count": 0,
                                    "review_retry_count": 1}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            launch.assert_not_called()
            self.assertTrue((base / "workspace/review.json").is_file())
            self.assertFalse((base / "workspace/repair-request.json").exists())

    def test_infra_error_with_approved_delivery_never_resumes_synthesis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-008"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/input/src").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 1.0}, "null": {"reward": 0.0},
                           "differential_from_final_bundle": {
                               "status": "failed",
                               "report": {"status": "infra_error", "success": False}}}}))
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "recovery_requested": True,
                                    "last_status": "harbor", "review_retry_count": 1,
                                    "retry_reason": "review_infrastructure"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertTrue(launch.call_args.kwargs["resume_harbor"])
            self.assertFalse(launch.call_args.kwargs["review_delivery"])

    def test_passing_gold_and_null_do_not_hide_stale_final_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-008"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 1.0}, "null": {"reward": 0.0},
                           "differential_from_final_bundle": {
                               "status": "failed", "report": {
                                   "branch": "FILE-POV", "status": "infra_error",
                                   "success": False, "vulnerable": {
                                       "error_stage": "submission",
                                       "error": "submission must exit 0 after the protocol exchange",
                                       "submission_result": {"returncode": 134}}}}}}))
            (base / "harbor/jobs").mkdir(parents=True)
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 1,
                                    "retry_reason": "review_infrastructure"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertTrue(launch.call_args.kwargs["resume_harbor"])
            self.assertTrue((base / "retry-evidence/harbor-file-pov-gold-protocol").is_dir())

    def test_genuine_gold_zero_is_not_an_infrastructure_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-016"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "workspace/review.json").write_text('{"passed": true}')
            (base / "result.json").write_text(json.dumps({
                "status": "failed", "failure_class": "harbor_failed",
                "harbor": {"gold": {"reward": 0.0},
                           "differential_from_final_bundle": {
                               "status": "passed", "report": {"success": True}}}}))
            evidence = base / "harbor/jobs/task-gold/trial/verifier"
            evidence.mkdir(parents=True)
            (evidence / "evidence.json").write_text(json.dumps({
                "branch": "FILE-POV", "status": "other_bug", "success": False,
                "vulnerable": {"submission_result": {"returncode": 0},
                               "oracle": {"returncode": 1}}}))
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "retry_count": 1,
                                    "retry_reason": "review_infrastructure"}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertFalse(launch.called)
            self.assertTrue((base / "harbor").is_dir())

    def test_completed_delivery_review_uses_review_delivery_not_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = "linux-011"
            (root / "selection.jsonl").write_text(
                json.dumps({"task_id": task, "instance_id": "CVE-test::project"}) + "\n")
            base = root / task
            (base / "workspace/delivery").mkdir(parents=True)
            (base / "workspace/input/src").mkdir(parents=True)
            (base / "workspace/route.json").write_text("{}")
            (base / "review").mkdir()
            (base / "review/result.json").write_text('{"status": "completed"}')
            (base / "result.json").write_text(json.dumps({"status": "reviewing"}))
            (base / "synthesis").mkdir()
            (base / "synthesis/result.json").write_text('{"status": "completed"}')
            (root / "supervisor-state.json").write_text(json.dumps({
                "children": {task: {"pid": None, "review_incomplete_retry_count": 0}}}))
            with unittest.mock.patch.object(supervise, "launch") as launch, \
                    unittest.mock.patch.object(supervise, "pipeline_worker_command", return_value=None):
                launch.return_value.pid = 4321
                with unittest.mock.patch("sys.argv", ["supervise", "--sample", str(root),
                                                       "--results", str(root), "--only", task, "--once"]):
                    self.assertEqual(supervise.main(), 0)
            self.assertTrue(launch.call_args.kwargs["review_delivery"])
            self.assertFalse(launch.call_args.kwargs["resume_harbor"])
            self.assertEqual(launch.call_args.args[4], 18000)


if __name__ == "__main__":
    unittest.main()


class ClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ["PIPELINE_CLAIM_DIR"] = str(Path(self.tmp) / "claims")
        self.addCleanup(os.environ.pop, "PIPELINE_CLAIM_DIR", None)
        self.addCleanup(os.environ.pop, "PIPELINE_PEER_RESULTS", None)

    def test_claim_is_exclusive_between_live_supervisors(self):
        self.assertTrue(supervise.claim_task("linux-1", "owner-a"))
        with unittest.mock.patch.object(supervise, "_supervise_alive", return_value=True):
            self.assertFalse(supervise.claim_task("linux-1", "owner-b"))
        self.assertTrue(supervise.claim_task("linux-1", "owner-a"))

    def test_stale_claim_is_stolen_without_peer_terminal(self):
        self.assertTrue(supervise.claim_task("linux-2", "owner-a"))
        self.assertTrue(supervise.claim_task("linux-2", "owner-b"))

    def test_peer_terminal_blocks_the_steal(self):
        self.assertTrue(supervise.claim_task("linux-3", "owner-a"))
        peer = Path(self.tmp) / "results-b" / "linux-3"
        peer.mkdir(parents=True)
        (peer / "result.json").write_text('{"status": "passed"}')
        os.environ["PIPELINE_PEER_RESULTS"] = str(Path(self.tmp) / "results-b")
        self.assertFalse(supervise.claim_task("linux-3", "owner-b"))

    def test_claim_dir_unset_allows_everything(self):
        os.environ.pop("PIPELINE_CLAIM_DIR", None)
        self.assertTrue(supervise.claim_task("linux-4", "owner-a"))
        self.assertTrue(supervise.claim_task("linux-4", "owner-b"))
