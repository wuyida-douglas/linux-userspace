from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.contract_build import build_task_contract


class ContractBuildTests(unittest.TestCase):
    def delivery(self, root: Path, branch: str = "SVC-EXPLOIT") -> tuple[Path, Path]:
        delivery = root / "delivery"
        workspace = root / "workspace"
        (delivery / "environment").mkdir(parents=True)
        workspace.mkdir()
        (workspace / "route.json").write_text(json.dumps({
            "branch": branch,
            "host_type": "native_service" if branch == "SVC-EXPLOIT" else None,
            "instance_id": "CVE-2026-1::https://github.com/acme/app",
        }))
        (delivery / "environment/docker-compose.yaml").write_text("""
services:
  main:
    image: analysis-main:1
  client:
    image: app-client:1
  db:
    image: postgres:16
""")
        return delivery, workspace

    def test_compose_is_authoritative_for_images_and_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery, workspace = self.delivery(Path(directory))
            built = build_task_contract(delivery, workspace)
            self.assertEqual(built["images"], {
                "agent": "analysis-main:1", "target": "app-client:1"})
            self.assertEqual(built["sidecar_services"], ["db"])
            self.assertEqual(built["healthcheck"]["argv"], ["/healthcheck.sh"])
            self.assertEqual(built["restart_command"], [])
            self.assertEqual(built["runner_network_aliases"], [])
            self.assertEqual(built["interaction"], "protocol")
            self.assertEqual(json.loads((delivery / "task.json").read_text())["images"],
                             built["images"])

    def test_file_pov_declares_public_runner_in_compose(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery, workspace = self.delivery(Path(directory), "FILE-POV")
            with self.assertRaises(ValueError):
                build_task_contract(delivery, workspace)
            (delivery / "environment/docker-compose.yaml").write_text("""
services:
  main:
    image: analysis-main:1
  client:
    image: app-client:1
    x-public-runner:
      argv: ["/usr/local/bin/pov-runner.sh", "{input}"]
""")
            built = build_task_contract(delivery, workspace)
            self.assertEqual(built["submission_mode"], "input.bin")
            self.assertEqual(built["public_runner"]["argv"],
                             ["/usr/local/bin/pov-runner.sh", "{input}"])
            self.assertEqual(built["healthcheck"]["argv"], ["/healthcheck.sh"])

    def test_legacy_frozen_public_runner_is_preserved_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery, workspace = self.delivery(Path(directory), "FILE-POV")
            (delivery / "task.json").write_text(json.dumps({
                "public_runner": {"argv": ["/usr/local/bin/pov-runner.sh", "{input}"]},
                "restart_command": ["/usr/local/bin/restart-app.sh"],
                "runner_network_aliases": ["fleet-mgmt"],
                "runner": {"image": "old-runner:1", "timeout_sec": 600},
            }))
            built = build_task_contract(delivery, workspace)
            self.assertEqual(built["public_runner"]["argv"],
                             ["/usr/local/bin/pov-runner.sh", "{input}"])
            self.assertEqual(built["restart_command"], ["/usr/local/bin/restart-app.sh"])
            self.assertEqual(built["runner_network_aliases"], ["fleet-mgmt"])
            self.assertEqual(built["runner"]["timeout_sec"], 600)
            # The runner image always follows the main analysis image.
            self.assertIsNone(built["runner"]["image"])

    def test_legacy_runner_command_is_preserved_for_svc_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery, workspace = self.delivery(Path(directory))
            (delivery / "task.json").write_text(json.dumps({
                "runner": {"command": ["python3", "/workspace/custom.py"],
                           "health_timeout_sec": 120},
            }))
            built = build_task_contract(delivery, workspace)
            self.assertEqual(built["runner"]["command"],
                             ["python3", "/workspace/custom.py"])
            self.assertEqual(built["runner"]["health_timeout_sec"], 120)

    def test_compose_main_image_is_authoritative_over_existing_task_json(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery, workspace = self.delivery(Path(directory))
            (delivery / "task.json").write_text(json.dumps({
                "images": {"agent": "stale-main:1", "target": "stale-client:1"},
            }))
            built = build_task_contract(delivery, workspace)
            self.assertEqual(built["images"], {
                "agent": "analysis-main:1", "target": "app-client:1"})


if __name__ == "__main__":
    unittest.main()