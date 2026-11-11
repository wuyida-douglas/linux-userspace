from __future__ import annotations

import json
import argparse
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import run
from pipeline.harbor import validate_public_services
from pipeline.pass2fail_verifier import Differential, VerifierInfraError, fresh_verify
from pipeline.prompts import REVIEW, SYNTHESIZE
from pipeline.task_contract import load_task, normalize_declared_metadata, normalize_sidecars


class PublicContractTests(unittest.TestCase):
    def services(self):
        return {"main": {"image": "agent:1", "healthcheck": {"test": ["CMD", "true"]}},
                "client": {"image": "target:1", "healthcheck": {"test": ["CMD", "true"]}}}

    def test_short_port_is_host_publication(self):
        value = self.services()
        value["client"]["ports"] = ["8080"]
        with self.assertRaisesRegex(ValueError, "isolated networks, not host ports"):
            validate_public_services(value)

    def test_weakened_network_and_mounts_are_rejected(self):
        for key, setting in (("network_mode", "host"), ("cap_add", ["NET_ADMIN"]),
                             ("container_name", "shared-target"),
                             ("security_opt", ["seccomp=unconfined"]),
                             ("volumes", ["/tmp/data:/data:ro"]),
                             ("volumes", ["shared:/data"]),
                             ("environment", {"HTTP_PROXY": "http://proxy:3128"}),
                             ("environment", {"no_proxy": "localhost"})):
            with self.subTest(key=key):
                value = self.services()
                value["client"][key] = setting
                with self.assertRaises(ValueError):
                    validate_public_services(value)

    def test_public_assets_are_not_rejected_by_name_substrings(self):
        value = self.services()
        value["client"]["volumes"] = ["./fixed-assets:/assets:ro", "./private-data:/data:ro"]
        value["client"]["healthcheck"] = {
            "test": ["CMD-SHELL", "test -f /vault/private/ready"]}
        validate_public_services(value)

    def test_static_ip_and_development_lease_do_not_enter_public_contract(self):
        value = self.services()
        value["client"]["networks"] = {"default": {"ipv4_address": "10.80.1.9"}}
        with self.assertRaisesRegex(ValueError, "static IP"):
            validate_public_services(value)

    def test_prompt_discloses_host_port_and_hard_contract(self):
        from pipeline.prompts import BRANCH_GUIDES
        combined = SYNTHESIZE + REVIEW + "".join(BRANCH_GUIDES.values())
        for text in ("DO NOT add `ports:`", "nonempty and <=16 MiB", "/usr/bin/env",
                     "exit exactly 0 when the vulnerability effect is present and 1", "0755",
                     "file_capability_inheritance", "runner_network_aliases",
                     "umask 022", "host/external/shared networks"):
            self.assertIn(text, combined)

    def contract(self, user):
        return {"schema_version": 1, "branch": "SVC-EXPLOIT", "host_type": "native_service",
                "interaction": "protocol", "submission_mode": "exploit.py", "target_service": "client",
                "images": {"agent": "agent:1", "target": "target:1"},
                "healthcheck": {"argv": ["/healthcheck.sh"]},
                "oracle": {"argv": ["/private/oracle.sh"]}, "solution": {"argv": ["/private/solution.sh"]},
                "runner": {"image": None, "workdir": "/workspace", "user": user,
                           "timeout_sec": 60, "health_timeout_sec": 60, "command": []}}

    def test_zero_uid_or_gid_is_rejected_early(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "task.json"
            for user in ("0:65534", "65534:0"):
                path.write_text(json.dumps(self.contract(user)))
                with self.assertRaisesRegex(ValueError, "uid 0 or gid 0"):
                    load_task(path)

    def test_file_null_string_is_normalized_only_with_matching_route(self):
        task = self.contract("65534:65534")
        route = {"branch": "FILE-POV", "host_type": None}
        task.update(branch="FILE-POV", host_type="null",
                    healthcheck={"argv": ["/healthcheck.sh"]})
        self.assertEqual(normalize_declared_metadata(task, route), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            delivery = root / "delivery"
            (delivery / "environment").mkdir(parents=True)
            (delivery / "task.json").write_text(json.dumps(task))
            (delivery / "environment/docker-compose.yaml").write_text(
                "services:\n  main: {}\n  client: {}\n")
            (root / "route.json").write_text(json.dumps(route))
            run.normalize_delivery_metadata(delivery, root, root)
            normalized = json.loads((delivery / "task.json").read_text())
            self.assertIsNone(normalized["host_type"])
            self.assertTrue((root / "retry-evidence/metadata-normalization/task.json").is_file())
            for spelling in ("none", "linux-container"):
                task["host_type"] = spelling
                (delivery / "task.json").write_text(json.dumps(task))
                run.normalize_delivery_metadata(delivery, root, root)
                self.assertIsNone(json.loads((delivery / "task.json").read_text())["host_type"])
        mismatched = self.contract("65534:65534")
        mismatched.update(branch="FILE-POV", host_type="null",
                          healthcheck={"argv": ["/healthcheck.sh"]})
        self.assertEqual(normalize_declared_metadata(mismatched, {"branch": "SVC-EXPLOIT"}), [])

    def test_sidecar_objects_are_normalized_only_against_real_compose(self):
        task = {"sidecar_services": [{"service": "mongo", "image": "mongo:4",
                                     "purpose": "target dependency"}]}
        services = {"main": {}, "client": {}, "mongo": {"image": "mongo:4"}}
        self.assertEqual(normalize_sidecars(task, services), ["mongo"])
        with self.assertRaisesRegex(ValueError, "real non-main"):
            normalize_sidecars(task, {"main": {}, "client": {}})
        with self.assertRaises(ValueError):
            normalize_sidecars({"sidecar_services": [{"image": "mongo:4"}]}, services)
        with self.assertRaises(ValueError):
            normalize_sidecars({"sidecar_services": ["main"]}, services)

    def test_carry_normalizes_before_review_without_touching_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            (task / "workspace/delivery/environment").mkdir(parents=True)
            contract = self.contract("65534:65534")
            original_sidecars = [{"service": "mongo", "image": "mongo:4",
                                  "purpose": "target dependency"}]
            contract["sidecar_services"] = original_sidecars
            (task / "workspace/delivery/task.json").write_text(json.dumps(contract))
            (task / "workspace/delivery/environment/docker-compose.yaml").write_text(
                "services:\n  main:\n    image: agent:1\n    healthcheck:\n      test: ['CMD', 'true']\n"
                "  client:\n    image: target:1\n    healthcheck:\n      test: ['CMD', 'true']\n"
                "  mongo:\n    image: mongo:4\n    healthcheck:\n      test: ['CMD', 'true']\n")
            for name in ("healthcheck.sh", "oracle.sh", "solution.sh"):
                path = task / "workspace/delivery/private" / name
                path.parent.mkdir(exist_ok=True)
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
            (task / "workspace/delivery/private/gold").mkdir()
            (task / "workspace/delivery/private/gold/exploit.py").write_text("print('test')\n")
            (task / "workspace/delivery/project").mkdir()
            (task / "workspace/delivery/project/source-recovery.json").write_text("{}")
            (task / "workspace/delivery/instruction.md").write_text("Test task\n")
            (task / "workspace/route.json").write_text(json.dumps(contract | {
                "instance_id": "CVE-test::project", "accepted": True,
                "reason": "The real native HTTP service exposes the target vulnerability.",
                "entry": "Unauthenticated HTTP request reaches the target service.",
                "oracle": "The target returns sensitive data before the patch and not afterward.",
                "normal_input": "A benign request is handled normally.",
                "fixed_revision": "UNRESOLVED", "recovery_required": True}))
            (task / "result.json").write_text('{"instance_id": "CVE-test::project"}')
            selection = {"instance_id": "CVE-test::project"}
            args = argparse.Namespace(resume=True, review_delivery=False, route_from=None,
                                      route_only=False,
                                      model="test", review_turns=1, review_timeout=1,
                                      verify_timeout=1, published_root=None)
            called = []
            def review(prompt, workspace, output, **kwargs):
                contract = json.loads((workspace / "delivery/task.json").read_text())
                called.append(contract["sidecar_services"])
                (workspace / "review.json").write_text(json.dumps({
                    "passed": False,
                    "evidence": "The test reviewer rejected the delivery."}))
                return {"status": "completed"}
            with patch("pipeline.agent.run", side_effect=review):
                record = run.run_one(task, selection, root, args, {})
            self.assertEqual(called, [["mongo"]], record)
            self.assertEqual(record["failure_class"], "review_rejected", record)
            self.assertIsInstance(original_sidecars[0], dict)
            self.assertTrue((task / "retry-evidence/contract-build/task.json").is_file())

    def test_final_verifier_uses_the_frozen_full_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "tests/private"
            private.mkdir(parents=True)
            (private / "task.json").write_text(json.dumps(self.contract("0:65534")))
            from pipeline.pass2fail_verifier import load_contract
            with self.assertRaisesRegex(ValueError, "uid 0 or gid 0"):
                load_contract(root)


class FreshWorkspaceTests(unittest.TestCase):
    def test_fresh_input_is_copied_once_before_route_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            (task / "input/src").mkdir(parents=True)
            (task / "input/meta.json").write_text('{"instance_id": "instance"}')
            selection = {"instance_id": "instance"}
            args = argparse.Namespace(
                resume=False, review_delivery=False, route_from=None,
                route_only=False,
                model="test", route_turns=1,
                route_timeout=1, review_turns=1, review_timeout=1,
                verify_timeout=1, published_root=None)
            called = []
            def route_agent(prompt, workspace, output, **kwargs):
                called.append(str(workspace))
                self.assertTrue((workspace / "input/src").is_dir())
                self.assertTrue((workspace / "NETWORK.md").is_file())
                return {"status": "completed"}
            with patch("pipeline.agent.run", side_effect=route_agent):
                record = run.run_one(task, selection, root, args, {})
            self.assertEqual(record["failure_class"], "route_decision_missing", record)
            self.assertEqual(len(called), 1)


class OracleContractTests(unittest.TestCase):
    def differential(self):
        return Differential.__new__(Differential)

    def test_patched_probe_error_is_not_patch_success(self):
        differential = self.differential()
        differential.contract = {"branch": "FILE-POV"}
        differential.prepare = lambda: None
        differential.phase = lambda name: ({"triggered": True} if name == "vulnerable" else
                                           {"triggered": False, "oracle": {"returncode": 126},
                                            "patched_health": {"returncode": 0}})
        result = differential.run()
        self.assertEqual(result["status"], "infra_error")
        self.assertEqual(result["reward"], 0.0)
        self.assertFalse(result["success"])

    def test_oracle_exit_126_is_infrastructure_failure(self):
        differential = self.differential()
        differential.contract = {"branch": "SVC-EXPLOIT",
                                 "runner": {"user": "65534:65534", "timeout_sec": 30, "health_timeout_sec": 30},
                                 "oracle": {"argv": ["/private/oracle.sh"]}}
        differential.project = "oracle-test"
        differential.docker = "docker-test"
        differential.upload_private = lambda project: {"returncode": 0, "output": ""}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        differential.runner = Path(directory.name)
        (differential.runner / "output").mkdir()

        def compose(*args, **kwargs):
            # Preserve the fixture's real evidence file across mocked cleanup.
            (differential.runner / "output/result.json").write_text('{"returncode": 0}')
            if "/private/oracle.sh" in args:
                return {"returncode": 126, "output": "Permission denied"}
            return {"returncode": 0, "output": ""}

        differential.compose = compose
        import os
        from pipeline import docker_ipam
        with patch.dict(os.environ, {"PASS2FAIL_KEEP_CONTAINERS": "1"}), \
                patch("pipeline.pass2fail_verifier.bounded_run", return_value={"returncode": 0, "output": ""}), \
                patch("importlib.util.spec_from_file_location") as spec, \
                patch("pipeline.pass2fail_verifier.subprocess.run"), \
                patch("importlib.util.module_from_spec") as module:
            helper = unittest.mock.MagicMock()
            helper.release_compose_subnets.return_value = ["10.112.1.0/24"]
            module.return_value = helper
            spec.return_value = unittest.mock.MagicMock()
            result = differential.phase("vulnerable")
        self.assertEqual(result.get("error_stage"), "oracle", result)
        self.assertNotIn("triggered", result)
        self.assertEqual(result["ipam_release"], ["10.112.1.0/24"])

    def test_synthesis_reroute_preserves_route_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            workspace = task / "workspace"
            (task / "input/src").mkdir(parents=True)
            (task / "input/meta.json").write_text('{"instance_id": "instance"}')
            (task / "input/fix.diff").write_text("diff --git a/a b/a\n")
            route_value = {
                "instance_id": "instance", "accepted": True,
                "branch": "SVC-EXPLOIT", "host_type": "native_service",
                "recovery_required": True, "fixed_revision": "UNRESOLVED",
                "entry": "protocol request", "oracle": "unauthorized effect",
                "normal_input": "normal request", "reason": "network attack path"}
            args = argparse.Namespace(resume=False, review_delivery=False, route_from=None,
                                      route_only=False, model="test",
                                      max_turns=1, timeout=1,
                                      route_turns=1, route_timeout=1,
                                      review_turns=1, review_timeout=1,
                                      verify_timeout=1, published_root=None)

            def executor(prompt, current, output, **kwargs):
                from pipeline.common import write_json
                if not (current / "route.json").is_file():
                    write_json(current / "route.json", route_value)
                    return {"status": "completed"}
                self.assertIn("Branch guide -- SVC-EXPLOIT", prompt)
                self.assertNotIn("Branch guide -- FILE-POV", prompt)
                write_json(current / "reroute-request.json", route_value | {
                    "branch": "FILE-POV", "host_type": None,
                    "reason": "Only a file-triggered crash was demonstrated."})
                return {"status": "completed"}

            with patch.object(run, "agent", unittest.mock.Mock(run=executor)):
                result = run.run_one(task, {"instance_id": "instance"}, root, args, {})
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_class"], "branch_mismatch")
            self.assertEqual(json.loads((workspace / "route.json").read_text()), route_value)

    def test_common_synthesis_defers_branch_specific_contracts(self):
        from pipeline.prompts import BRANCH_GUIDES, SYNTHESIZE
        for branch_only in ("ASAN_OPTIONS", "public_runner", "reroute-request.json",
                            'interaction="protocol"', 'interaction="interactive_file"',
                            'interaction="file_pov"',
                            "SVC-EXPLOIT", "FILE-EXPLOIT", "FILE-POV"):
            self.assertNotIn(branch_only, SYNTHESIZE)
        self.assertNotIn("SVC-EXPLOIT and FILE-EXPLOIT reference submission", SYNTHESIZE)
        self.assertIn("ASAN_OPTIONS", BRANCH_GUIDES["FILE-POV"])
        self.assertIn("public_runner", BRANCH_GUIDES["FILE-POV"])
        self.assertIn('interaction="protocol"', BRANCH_GUIDES["SVC-EXPLOIT"])
        self.assertIn('interaction="interactive_file"', BRANCH_GUIDES["FILE-EXPLOIT"])
        for branch, other in (("SVC-EXPLOIT", ("FILE-EXPLOIT", "FILE-POV")),
                              ("FILE-EXPLOIT", ("SVC-EXPLOIT", "FILE-POV"))):
            guide = BRANCH_GUIDES[branch]
            self.assertIn("reroute-request.json", guide)
            self.assertIn("evidence", guide)
            for name in other:
                self.assertNotIn(name, guide)

    
    def test_review_requires_an_ordinary_complete_json_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "review.json").write_text('{"passed": false}')
            with self.assertRaisesRegex(ValueError, "review.json must include"):
                run.review(root)
            (root / "review.json").write_text(
                '{"passed": false, "evidence": "oracle trusts submission stdout"}')
            self.assertEqual(run.review(root),
                             {"passed": False, "evidence": "oracle trusts submission stdout"})
            (root / "review.json").write_text(
                '{"passed": false, "evidence": "oracle trusts submission stdout", "notes": "advisory"}')
            self.assertEqual(run.review(root),
                             {"passed": False, "evidence": "oracle trusts submission stdout"})

    def test_runner_uses_path_lookup_for_portable_python(self):
        differential = self.differential()
        with tempfile.TemporaryDirectory() as directory:
            differential.runner = Path(directory)
            differential._write_runner()
            runner = differential.runner / "runner.py"
            self.assertEqual(runner.read_text().splitlines()[0], "#!/usr/bin/env python3")
            self.assertEqual(runner.stat().st_mode & 0o777, 0o755)

    def test_health_and_submission_do_not_reuse_an_old_result_file(self):
        differential = self.differential()
        differential.contract = {"branch": "SVC-EXPLOIT",
                                 "runner": {"user": "65534:65534", "timeout_sec": 30,
                                            "health_timeout_sec": 30},
                                 "oracle": {"argv": ["/private/oracle.sh"]}}
        differential.project = "fresh-probe-test"
        differential.docker = "docker-test"
        differential.upload_private = lambda project: {"returncode": 0, "output": ""}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        differential.runner = Path(directory.name)
        (differential.runner / "output").mkdir()
        (differential.runner / "output/result.json").write_text('{"returncode": 125}')
        probes = []

        def compose(*args, **kwargs):
            probes.append(args)
            if args[-1] == "down":
                return {"returncode": 0, "output": ""}
            if "/opt/pass2fail/runner.py" in args:
                assert not (differential.runner / "output/result.json").exists()
                (differential.runner / "output/result.json").write_text('{"returncode": 0}')
            return {"returncode": 0, "output": ""}

        differential.compose = compose
        with patch("pipeline.pass2fail_verifier.subprocess.run"), \
                patch("pipeline.pass2fail_verifier.bounded_run", return_value={"returncode": 0, "output": ""}), \
                patch("importlib.util.spec_from_file_location") as spec, \
                patch("importlib.util.module_from_spec") as module:
            helper = unittest.mock.MagicMock()
            helper.release_compose_subnets.return_value = []
            module.return_value = helper
            spec.return_value = unittest.mock.MagicMock()
            result = differential.phase("vulnerable")
        self.assertTrue(result["triggered"])
        runner_calls = [call for call in probes if "/opt/pass2fail/runner.py" in call]
        self.assertEqual(len(runner_calls), 2)
        self.assertEqual(runner_calls[0][-1], "--health")
        self.assertEqual(runner_calls[1][-1], "/opt/pass2fail/runner.py")

    def test_each_phase_has_fresh_unprivileged_scratch_and_restores_evidence(self):
        differential = self.differential()
        differential.contract = {"branch": "SVC-EXPLOIT",
                                 "runner": {"user": "65534:65534"}}
        with tempfile.TemporaryDirectory() as directory:
            differential.runner = Path(directory)
            (differential.runner / "run").mkdir()
            (differential.runner / "output").mkdir()
            (differential.runner / "run/transcript.log").write_text("vulnerable")
            with patch("pipeline.pass2fail_verifier.subprocess.run") as run:
                differential._prepare_runner_mounts()
                self.assertEqual((differential.runner / "run-archives/000/transcript.log").read_text(),
                                 "vulnerable")
                self.assertFalse((differential.runner / "run/transcript.log").exists())
                (differential.runner / "run/transcript.log").write_text("fixed")
                differential._prepare_runner_mounts()
                self.assertEqual((differential.runner / "run-archives/001/transcript.log").read_text(),
                                 "fixed")
                differential._restore_runner_mounts()
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                *([["sudo", "-n", "chown", "65534:65534", str(mount)]
                   for _ in range(2) for mount in (differential.runner / "run",
                                                    differential.runner / "output")]),
                ["sudo", "-n", "chown", "-R", f"{differential.runner_owner[0]}:{differential.runner_owner[1]}",
                 str(differential.runner / "run"), str(differential.runner / "output")],
            ])

    def test_file_pov_crash_reaches_the_effect_oracle(self):
        differential = self.differential()
        differential.contract = {"branch": "FILE-POV",
                                 "runner": {"user": "65534:65534", "timeout_sec": 30,
                                            "health_timeout_sec": 30},
                                 "public_runner": {"argv": ["runner", "{input}"]},
                                 "oracle": {"argv": ["/private/oracle.sh"]}}
        differential.project = "file-pov-test"
        differential.docker = "docker-test"
        differential.upload_private = lambda project: {"returncode": 0, "output": ""}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        differential.runner = Path(directory.name)
        differential.file_input = differential.runner / "input"
        differential.file_input.mkdir()
        (differential.file_input / "input.bin").write_bytes(b"pov")
        called = []

        def compose(*args, **kwargs):
            called.append(args)
            if "runner" in args:
                return {"returncode": 134, "output": ""}
            return {"returncode": 0, "output": ""}

        differential.compose = compose
        with patch("pipeline.pass2fail_verifier.bounded_run", return_value={"returncode": 0, "output": ""}), \
                patch("importlib.util.spec_from_file_location") as spec, \
                patch("importlib.util.module_from_spec") as module:
            helper = unittest.mock.MagicMock()
            helper.release_compose_subnets.return_value = []
            module.return_value = helper
            spec.return_value = unittest.mock.MagicMock()
            result = differential.phase("vulnerable")
        self.assertTrue(result["triggered"])
        self.assertIn("/private/oracle.sh", called[-2])

    def test_runner_traceback_cannot_be_masked_by_oracle(self):
        differential = self.differential()
        differential.contract = {"branch": "SVC-EXPLOIT"}
        differential.prepare = lambda: None
        differential.phase = lambda name: {
            "submission": {"returncode": 1},
            "submission_result": {"returncode": 1, "output": "read-only filesystem"},
            "error_stage": "submission", "error": "submission must exit 0 after the protocol exchange",
        } if name == "vulnerable" else {"triggered": False}
        result = differential.run()
        self.assertEqual(result["status"], "infra_error")
        self.assertEqual(result["reward"], 0.0)
        self.assertFalse(result["success"])
        self.assertNotIn("fixed", result)

    def test_infrastructure_exception_has_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory) / "logs"
            with patch("pipeline.pass2fail_verifier.load_contract",
                       side_effect=PermissionError(13, "denied", "PKG-INFO")):
                with self.assertRaises(VerifierInfraError):
                    fresh_verify(Path(directory), Path(directory) / "exploit.py", log_dir)
            self.assertFalse((log_dir / "reward.json").exists())
            self.assertFalse((log_dir / "reward.txt").exists())
            saved = json.loads((log_dir / "evidence.json").read_text())
            self.assertEqual(saved["status"], "infra_error")
            self.assertIn("PermissionError", saved["traceback"])
            self.assertIn("PKG-INFO", saved["traceback"])

    def test_infra_status_does_not_write_reward(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submission = root / "exploit.py"
            submission.write_text("print(1)\n")
            log_dir = root / "logs"
            with patch("pipeline.pass2fail_verifier.load_contract", return_value={}), \
                    patch("pipeline.pass2fail_verifier.Differential") as differential, \
                    patch("pipeline.pass2fail_verifier._restore_public_binds"):
                differential.return_value.run.return_value = {
                    "schema_version": 2, "reward": 0.0, "status": "infra_error",
                    "success": False, "error": "target failed to start"}
                with self.assertRaises(VerifierInfraError):
                    fresh_verify(root, submission, log_dir)
            self.assertFalse((log_dir / "reward.json").exists())
            self.assertFalse((log_dir / "reward.txt").exists())
            saved = json.loads((log_dir / "evidence.json").read_text())
            self.assertEqual(saved["status"], "infra_error")


class FileExploitSubmissionTests(unittest.TestCase):
    def phase(self, branch, returncode):
        from pipeline.pass2fail_verifier import Differential
        verifier = Differential.__new__(Differential)
        verifier.contract = {"branch": branch, "runner": {"user": "65534:65534", "timeout_sec": 30,
                                                          "health_timeout_sec": 60},
                             "healthcheck": {"argv": ["/health"]}, "solution": {"argv": ["/solution"]},
                             "oracle": {"argv": ["/oracle"]}}
        verifier.project = "isolated-test"
        verifier.docker = "docker"
        verifier.runner = Path(tempfile.mkdtemp())
        (verifier.runner / "output").mkdir()
        (verifier.runner / "output/result.json").write_text(json.dumps({"returncode": returncode}))
        calls = []
        def compose(*argv, **kwargs):
            calls.append(argv)
            if "exec" in argv and argv[-1] == "/opt/pass2fail/runner.py":
                (verifier.runner / "output/result.json").write_text(json.dumps({"returncode": returncode}))
            return {"returncode": 0, "output": ""}
        with patch.object(verifier, "compose", side_effect=compose), \
                patch.object(verifier, "upload_private", return_value={"returncode": 0}), \
                patch.object(verifier, "_prepare_runner_mounts"), \
                patch("pipeline.pass2fail_verifier.bounded_run", return_value={"returncode": 0, "output": ""}):
            record = verifier.phase("fixed")
        return record, calls

    def test_documented_patched_exploit_exit_one_reaches_target_oracle(self):
        record, calls = self.phase("FILE-EXPLOIT", 1)
        self.assertNotIn("error_stage", record)
        self.assertTrue(any("/oracle" in argv for argv in calls))

    def test_expected_patched_service_rejection_reaches_target_oracle(self):
        record, calls = self.phase("SVC-EXPLOIT", 1)
        self.assertNotIn("error_stage", record)
        self.assertIn("oracle", record)
        self.assertTrue(any("/oracle" in argv for argv in calls))

    def test_service_protocol_failure_remains_an_error(self):
        record, calls = self.phase("SVC-EXPLOIT", 2)
        self.assertEqual(record["error_stage"], "submission")
        self.assertFalse(any("/oracle" in argv for argv in calls))


class CarriedInputTests(unittest.TestCase):
    def test_carried_worker_binds_copied_input_and_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample, results = root / "sample", root / "results"
            sample.mkdir()
            (sample / "selection.jsonl").write_text("")
            task = results / "linux-001"
            (task / "workspace/input/src").mkdir(parents=True)
            instance = "CVE-test::https://github.com/example/project"
            (task / "carry-provenance.json").write_text(json.dumps({
                "same_instance_continuation": True, "instance_id": instance}))
            (task / "result.json").write_text(json.dumps({
                "task_id": "linux-001", "instance_id": instance}))
            (task / "workspace/route.json").write_text(json.dumps({"instance_id": instance}))
            (task / "workspace/input/meta.json").write_text(json.dumps({"instance_id": instance}))
            captured = {}
            def worker(task_path, selection, *_):
                captured.update(task=task_path, selection=selection)
                return {"task_id": selection["task_id"], "status": "passed"}
            with patch.object(run, "load_env", return_value={}), \
                    patch.object(run, "run_exclusive", side_effect=worker), \
                    patch("sys.argv", ["run", "--sample", str(sample), "--results", str(results),
                                       "--only", "linux-001"]):
                self.assertEqual(run.main(), 0)
            self.assertEqual(captured["task"], task / "workspace")
            self.assertEqual(captured["selection"]["instance_id"], instance)

    def test_carried_worker_rejects_an_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample, task = root / "sample", root / "results/linux-001"
            sample.mkdir()
            (sample / "selection.jsonl").write_text("")
            (task / "workspace/input/src").mkdir(parents=True)
            (task / "carry-provenance.json").write_text(json.dumps({
                "same_instance_continuation": True, "instance_id": "CVE-real::project"}))
            (task / "result.json").write_text(json.dumps({
                "task_id": "linux-001", "instance_id": "CVE-other::project"}))
            with patch.object(run, "load_env", return_value={}), \
                    patch("sys.argv", ["run", "--sample", str(sample), "--results", str(root / "results"),
                                       "--only", "linux-001"]):
                with self.assertRaisesRegex(ValueError, "no valid input|identity mismatch"):
                    run.main()


if __name__ == "__main__":
    unittest.main()
