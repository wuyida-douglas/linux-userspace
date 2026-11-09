from __future__ import annotations

import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from pipeline.iterate_batches import (adopt_existing_carries, batch_candidates, classify,
                                      preserve_missing_input_result, recovery_instance)


class BatchAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.task = self.root / "linux-001"
        (self.task / "workspace").mkdir(parents=True)

    def tearDown(self):
        self.temporary.cleanup()

    def test_strict_acceptance_requires_every_real_contract(self):
        row = {"status": "passed", "review": {"passed": True}, "harbor": {
            "gold": {"reward": 1.0}, "null": {"reward": 0.0},
            "differential_from_final_bundle": {"status": "passed", "report": {"success": True}}}}
        self.assertEqual(classify(self.task.name, row, self.root)["classification"],
                         "strict_harbor_acceptance")
        row["harbor"]["gold"]["reward"] = 0.0
        self.assertNotEqual(classify(self.task.name, row, self.root)["classification"],
                            "strict_harbor_acceptance")

    def test_not_suitable_and_review_rejection_are_not_pipeline_repairs(self):
        rejected = {"status": "rejected", "failure_class": "not_suitable"}
        self.assertEqual(classify(self.task.name, rejected, self.root)["classification"],
                         "genuine_routing_rejection")
        reviewed = {"status": "failed", "failure_class": "review_rejected"}
        result = classify(self.task.name, reviewed, self.root)
        self.assertEqual(result["classification"], "delivery_or_oracle_failure")
        self.assertIsNone(result["recovery_reason"])

    def test_synthesis_interruption_is_bounded_recovery_not_a_second_vote(self):
        (self.task / "workspace/route.json").write_text("{}")
        row = {"status": "failed", "failure_class": "synthesis_incomplete"}
        result = classify(self.task.name, row, self.root)
        self.assertEqual(result["classification"], "pipeline_recovery_candidate")
        self.assertEqual(result["recovery_reason"], "synthesis_interrupted")

    def test_partial_max_turn_delivery_is_synthesis_not_fake_review_recovery(self):
        (self.task / "workspace/route.json").write_text("{}")
        (self.task / "workspace/delivery/private").mkdir(parents=True)
        (self.task / "synthesis").mkdir()
        (self.task / "synthesis/result.json").write_text('{"status": "max_turns"}')
        row = {"status": "error", "failure_class": "pipeline",
               "error": "ValueError: missing delivery/task.json"}
        result = classify(self.task.name, row, self.root)
        self.assertEqual(result["classification"], "pipeline_recovery_candidate")
        self.assertEqual(result["recovery_reason"], "synthesis_interrupted")

    def test_exhausted_route_has_only_its_existing_budget_recovery(self):
        row = {"status": "error", "failure_class": "pipeline",
               "error": "RuntimeError: routing agent did not complete: max_turns"}
        result = classify(self.task.name, row, self.root)
        self.assertEqual(result["classification"], "pipeline_recovery_candidate")
        self.assertEqual(result["recovery_reason"], "route_budget")

    def test_exhausted_route_does_not_buy_another_budget_after_handoff(self):
        (self.root / "supervisor-state.json").write_text(json.dumps({
            "children": {self.task.name: {"route_budget_recovery_count": 1}}
        }))
        row = {"status": "error", "failure_class": "pipeline",
               "error": "RuntimeError: routing agent did not complete: max_turns"}
        result = classify(self.task.name, row, self.root)
        self.assertEqual(result["classification"], "terminal_failure")
        self.assertEqual(result["retry_blocked"], "route_budget_already_launched")
        self.assertIsNone(result["recovery_reason"])

    def test_exhausted_synthesis_does_not_buy_another_full_session(self):
        (self.task / "workspace/route.json").write_text("{}")
        (self.task / "workspace/input/src").mkdir(parents=True, exist_ok=True)
        (self.task / "synthesis").mkdir()
        (self.task / "synthesis/result.json").write_text('{"status": "max_turns"}')
        (self.root / "supervisor-state.json").write_text(json.dumps({
            "children": {self.task.name: {"bounded_recovery_launched": True}}
        }))
        row = {"status": "error", "failure_class": "pipeline",
               "error": "ValueError: missing delivery/task.json"}
        result = classify(self.task.name, row, self.root)
        self.assertEqual(result["classification"], "terminal_failure")
        self.assertEqual(result["retry_blocked"], "bounded_recovery_already_launched")
        self.assertIsNone(result["recovery_reason"])

    def test_failed_gold_protocol_requires_code_fix_not_acceptance_retry(self):
        (self.task / "workspace/route.json").write_text("{}")
        row = {"status": "failed", "failure_class": "harbor_failed", "harbor": {
            "gold": {"reward": 0.0},
            "differential_from_final_bundle": {"status": "failed", "report": {"status": "infra_error"}}}}
        result = classify(self.task.name, row, self.root)
        self.assertEqual(result["classification"], "pipeline_fix_required")
        self.assertIsNone(result["recovery_reason"])

    def test_existing_carry_adoption_checks_identity_and_recovery_receipt(self):
        source = self.root / "source" / self.task.name
        source.mkdir(parents=True)
        (source / "result.json").write_text('{"instance_id": "CVE-test::project"}')
        results = self.root / "results"
        destination = results / self.task.name
        destination.mkdir(parents=True)
        (destination / "carry-provenance.json").write_text(json.dumps({
            "source": str(source.resolve()), "instance_id": "CVE-test::project"}))
        (destination / "carry-recovery.json").write_text('{"mode": "synthesis"}')
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        adopt_existing_carries(results, {self.task.name: Path("source") / self.task.name})
        self.assertTrue(destination.exists())
        (destination / "carry-provenance.json").write_text(json.dumps({
            "source": str(source.resolve()), "instance_id": "different"}))
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            adopt_existing_carries(results, {self.task.name: source})

    def test_same_batch_carry_with_live_pid_is_adopted_without_new_budget(self):
        source = self.root / "source" / self.task.name
        source.mkdir(parents=True)
        (source / "result.json").write_text('{"instance_id": "CVE-test::project"}')
        results = self.root / "results"
        destination = results / self.task.name
        destination.mkdir(parents=True)
        (destination / "carry-provenance.json").write_text(json.dumps({
            "source": str(source.resolve()), "instance_id": "CVE-test::project"}))
        (destination / "carry-recovery.json").write_text('{"mode": "synthesis"}')
        (results / "supervisor-state.json").write_text(json.dumps({
            "children": {self.task.name: {"pid": 123, "bounded_recovery_launched": True}}}))
        adopt_existing_carries(results, {self.task.name: source})
        child = json.loads((results / "supervisor-state.json").read_text())["children"][self.task.name]
        self.assertNotIn("carry_blocked", child)
        self.assertTrue(child["bounded_recovery_launched"])

    def test_incomplete_result_uses_verified_route_identity(self):
        (self.task / "workspace/route.json").write_text(
            '{"instance_id": "CVE-test::project"}')
        self.assertEqual(recovery_instance(self.task, self.task.name),
                         "CVE-test::project")
        (self.task / "workspace/route.json").write_text('{}')
        with self.assertRaisesRegex(RuntimeError, "verifiable instance identity"):
            recovery_instance(self.task, self.task.name)

    def test_true_infra_differential_is_not_an_oracle_failure(self):
        (self.task / "workspace/route.json").write_text("{}")
        row = {"status": "failed", "failure_class": "harbor_failed", "harbor": {
            "gold": {"reward": 1.0},
            "differential_from_final_bundle": {"status": "error"}}}
        result = classify(self.task.name, row, self.root)
        self.assertEqual(result["recovery_reason"], "harbor_infrastructure")


class FrozenBatchCandidateTests(unittest.TestCase):
    def test_legacy_unavailable_inputs_keep_their_positions(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary)
            rows = [{"task_id": f"linux-{number:03d}", "instance_id": f"instance-{number}"}
                    for number in range(1, 101)]
            with (sample / "selection.jsonl").open("w") as stream:
                for row in rows:
                    stream.write(json.dumps(row) + "\n")
            (sample / "download-report.json").write_text(json.dumps({"tasks": [
                {"task_id": "linux-001", "status": "error", "error": "S3 unavailable"}]}))
            for row in rows[1:]:
                manifest = sample / "tasks" / row["task_id"] / "input/manifest.json"
                manifest.parent.mkdir(parents=True)
                manifest.write_text('{"status": "complete"}')
            candidates = batch_candidates(sample, 100, True)
            self.assertEqual([row["task_id"] for row in candidates],
                             [row["task_id"] for row in rows])
            (sample / "completed-selection.jsonl").unlink(missing_ok=True)
            with self.assertRaises(FileNotFoundError):
                batch_candidates(sample, 100, False)

    def test_unwritten_result_keeps_preserved_unavailable_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = "linux-030"
            report = {"tasks": [{"task_id": task, "instance_id": "CVE-test::project",
                                 "status": "error", "error": "S3 unavailable"}]}
            row = preserve_missing_input_result(root, task, {}, report)
            self.assertEqual(row["failure_class"], "input_unavailable")
            self.assertEqual(row["instance_id"], "CVE-test::project")
            self.assertEqual(classify(task, row, root)["classification"], "input_unavailable")
            existing = {"task_id": task, "status": "passed"}
            self.assertEqual(preserve_missing_input_result(root, task, existing, report), existing)

    def test_downstream_missing_input_result_restores_original_s3_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = "linux-030"
            report = {"tasks": [{"task_id": task, "instance_id": "CVE-test::project",
                                 "status": "error", "error": "meta.json missing in S3"}]}
            downstream = {"task_id": task, "instance_id": "CVE-test::project",
                          "status": "error", "failure_class": "pipeline",
                          "error": "FileNotFoundError: task input"}
            row = preserve_missing_input_result(root, task, downstream, report)
            self.assertEqual(classify(task, row, root)["classification"], "input_unavailable")
            self.assertEqual(row["error"], "meta.json missing in S3")
            self.assertEqual(row["downstream_result_preserved"], downstream)

    def test_legacy_receipt_reconciles_fourteen_fresh_and_twenty_five_observed(self):
        from pipeline.iterate_batches import initial_attribution
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "sample"
            sample.mkdir()
            source_receipt = None
            receipt = {"fresh": [f"fresh-{number}" for number in range(14)],
                       "carried": [], "observed_only": [f"observed-{number}" for number in range(25)]}
            for task in receipt["observed_only"] + [
                    "linux-030-cve-2014-6061-https-github-com-symfony-symfony"]:
                (root / task).mkdir(exist_ok=True)
                (root / task / "result.json").write_text('{"status": "error"}')
            (sample / "download-report.json").write_text(json.dumps({"tasks": [
                {"task_id": "linux-030-cve-2014-6061-https-github-com-symfony-symfony",
                 "status": "error", "error": "S3 missing"},
                {"task_id": "unattempted", "status": "error", "error": "S3 missing"}]}))
            attribution = initial_attribution(root, receipt, sample, set())
            self.assertEqual(len(attribution["fresh"]), 14)
            self.assertEqual(len(attribution["observed_only"]), 27)
            self.assertEqual(attribution["carried"], [])
            self.assertIn("unattempted", attribution["observed_only"])
            self.assertIn("linux-030-cve-2014-6061-https-github-com-symfony-symfony",
                          attribution["observed_only"])
            self.assertFalse(set(attribution["fresh"]) & set(attribution["observed_only"]))

    def test_all_unavailable_positions_enter_the_initial_observation_ledger(self):
        from pipeline.iterate_batches import initial_attribution
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "sample"
            sample.mkdir()
            (sample / "download-report.json").write_text(json.dumps({"tasks": [
                {"task_id": "unattempted", "status": "error", "error": "S3 missing"},
                {"task_id": "complete", "status": "complete"}]}))
            attribution = initial_attribution(root, {"fresh": ["complete"], "observed_only": []},
                                              sample, set())
            self.assertEqual(attribution["observed_only"], ["unattempted"])
            self.assertFalse((root / "unattempted").exists())




class CoordinatorRecoveryTests(unittest.TestCase):
    def test_audited_batch_never_relaunches_and_foreign_ids_do_not_consume_quota(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample, output, initial = root / "sample", root / "output", root / "initial"
            sample.mkdir(), output.mkdir(), initial.mkdir()
            rows = [{"task_id": f"linux-{number:03d}", "instance_id": f"instance-{number}"}
                    for number in range(1, 4)]
            for name in ("selection.jsonl", "completed-selection.jsonl"):
                (sample / name).write_text("".join(json.dumps(row) + "\n" for row in rows))
            for row in rows:
                manifest = sample / "tasks" / row["task_id"] / "input/manifest.json"
                manifest.parent.mkdir(parents=True)
                manifest.write_text('{"status": "complete"}')
                (initial / row["task_id"]).mkdir()
                (initial / row["task_id"] / "result.json").write_text(json.dumps({
                    "task_id": row["task_id"], "instance_id": row["instance_id"],
                    "status": "passed", "review": {"passed": True}, "harbor": {
                        "gold": {"reward": 1.0}, "null": {"reward": 0.0},
                        "differential_from_final_bundle": {"status": "passed",
                                                            "report": {"success": True}}}}))
            (output / "iteration-state.json").write_text(json.dumps({
                "schema_version": 1, "batches": [1],
                "attempted_fresh": ["linux-001", "legacy-017"],
                "active_batch": 2, "supervisor_pid": 999999}))
            for number in (1, 2):
                (output / f"batch-{number:03d}-audit.json").write_text(json.dumps({
                    "code_fix_review": {"approved": True}, "carry_sources": {},
                    "recovery_plans": {}, "batch": number}))
            launched = unittest.mock.Mock()
            launched.pid = 4321
            launched.wait.side_effect = KeyboardInterrupt
            with unittest.mock.patch("pipeline.iterate_batches.regression_gate"), \
                    unittest.mock.patch("pipeline.iterate_batches.subprocess.Popen", return_value=launched) as popen, \
                    unittest.mock.patch("pipeline.iterate_batches.os.kill", side_effect=ProcessLookupError), \
                    unittest.mock.patch("pipeline.iterate_batches.subprocess.run",
                                        return_value=unittest.mock.Mock(stdout="")), \
                    unittest.mock.patch("pipeline.iterate_batches.time.sleep", side_effect=KeyboardInterrupt), \
                    unittest.mock.patch("sys.argv", ["iterate_batches", "--sample", str(sample),
                                                       "--output", str(output), "--initial-results", str(initial),
                                                       "--initial-supervisor-pid", "0", "--initial-only", "linux-001",
                                                       "--batch-size", "1", "--concurrency", "1", "--target-size", "3"]):
                with self.assertRaises(KeyboardInterrupt):
                    from pipeline.iterate_batches import main
                    main()
            selection = json.loads((output / "batch-003/batch-selection.json").read_text())
            self.assertEqual(selection["fresh"], ["linux-002"])
            self.assertNotIn("legacy-017", json.loads(
                (output / "iteration-state.json").read_text())["attempted_fresh"])
            command = popen.call_args.args[0]
            self.assertIn("--results", command)
            self.assertTrue(command[command.index("--results") + 1].endswith("batch-003"))

    def test_invalid_legacy_receipt_is_rejected_before_any_launch(self):
        from pipeline.iterate_batches import validate_batch_selection
        with self.assertRaisesRegex(RuntimeError, "overlapping frozen selection"):
            validate_batch_selection({"batch": 2, "fresh": ["observed", "fresh"],
                                      "carried": ["observed"]}, 2, set())

    def test_observed_positions_never_reenter_fresh_or_overlap_carried(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample, output, initial = root / "sample", root / "output", root / "initial"
            sample.mkdir(), output.mkdir(), initial.mkdir()
            rows = [{"task_id": f"task-{number:03d}", "instance_id": f"instance-{number}"}
                    for number in range(1, 6)]
            (sample / "selection.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            for row in rows:
                (initial / row["task_id"]).mkdir()
                if row["task_id"] != "task-002":
                    manifest = sample / "tasks" / row["task_id"] / "input/manifest.json"
                    manifest.parent.mkdir(parents=True)
                    manifest.write_text('{"status": "complete"}')
            (initial / "batch-selection.json").write_text(json.dumps({
                "fresh": ["task-001"], "carried": [], "observed_only": ["task-002"]}))
            (initial / "task-001/result.json").write_text(json.dumps({
                "status": "passed", "review": {"passed": True}, "harbor": {
                    "gold": {"reward": 1.0}, "null": {"reward": 0.0},
                    "differential_from_final_bundle": {"status": "passed", "report": {"success": True}}}}))
            (initial / "task-002/result.json").write_text(json.dumps({
                "status": "error", "failure_class": "input_unavailable"}))
            (sample / "download-report.json").write_text(json.dumps({"tasks": [
                {"task_id": "task-002", "instance_id": "instance-2", "status": "error",
                 "error": "S3 missing"}]}))
            (output / "iteration-state.json").write_text(json.dumps({
                "batches": [1], "attempted_fresh": ["task-001"]}))
            (output / "batch-001-audit.json").write_text(json.dumps({
                "batch": 1, "code_fix_review": {"approved": True},
                "carry_sources": {}, "recovery_plans": {}}))
            launched = unittest.mock.Mock(pid=4321)
            launched.poll.return_value = 0
            launched.wait.side_effect = KeyboardInterrupt
            with unittest.mock.patch("pipeline.iterate_batches.regression_gate"), \
                    unittest.mock.patch("pipeline.iterate_batches.subprocess.Popen", return_value=launched) as popen, \
                    unittest.mock.patch("pipeline.iterate_batches.os.kill", side_effect=ProcessLookupError), \
                    unittest.mock.patch("pipeline.iterate_batches.subprocess.run",
                                        return_value=unittest.mock.Mock(stdout="")), \
                    unittest.mock.patch("pipeline.iterate_batches.time.sleep", side_effect=KeyboardInterrupt), \
                    unittest.mock.patch("sys.argv", ["iterate_batches", "--sample", str(sample),
                                                       "--output", str(output), "--initial-results", str(initial),
                                                       "--initial-supervisor-pid", "0", "--initial-only", "task-001",
                                                       "--initial-observed-only", "task-002", "--preserve-unavailable-inputs",
                                                       "--batch-size", "2", "--concurrency", "2", "--target-size", "5"]):
                with self.assertRaises(KeyboardInterrupt):
                    from pipeline.iterate_batches import main
                    main()
            receipt = json.loads((output / "batch-002/batch-selection.json").read_text())
            self.assertEqual(receipt["fresh"], ["task-003", "task-004"])
            self.assertNotIn("task-002", receipt["fresh"])
            command = popen.call_args.args[0]
            self.assertNotIn("task-002", command[command.index("--only") + 1:])


if __name__ == "__main__":
    unittest.main()
