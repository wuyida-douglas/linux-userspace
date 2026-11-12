from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import harbor


class RebuildMissingImagesTests(unittest.TestCase):
    def delivery(self, root: Path) -> Path:
        delivery = root / "delivery"
        for name in ("main", "client"):
            directory = delivery / "project" / name
            directory.mkdir(parents=True)
            (directory / "Dockerfile").write_text(f"FROM scratch-{name}\n", encoding="utf-8")
        return delivery

    def test_rebuilds_only_missing_task_images(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery = self.delivery(Path(directory))
            contract = {"images": {"agent": "demo-main:1", "target": "demo-client:1"}}
            calls: list[list[str]] = []

            class Completed:
                def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
                    self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

            def fake_run(argv, **kwargs):
                calls.append(argv)
                if argv[:4] == ["docker", "image", "inspect", "demo-main:1"]:
                    return Completed(0, "[]")
                if argv[:4] == ["docker", "image", "inspect", "demo-client:1"]:
                    return Completed(1, "", "missing")
                return Completed(0)

            with patch.object(harbor, "docker_argv", side_effect=lambda argv: argv), \
                    patch.object(harbor.subprocess, "run", side_effect=fake_run):
                rebuilt = harbor.rebuild_missing_images(delivery, contract)
            self.assertEqual(rebuilt, ["demo-client:1"])
            builds = [call for call in calls if call[:3] == ["docker", "build", "--network"]]
            self.assertEqual(len(builds), 1)
            self.assertIn("demo-client:1", builds[0])
            self.assertIn(str(delivery / "project"), builds[0])

    def test_shared_platform_image_is_never_rebuilt(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery = self.delivery(Path(directory))
            contract = {"images": {"agent": "linux-userspace-agent:22.04",
                                   "target": "demo-client:1"}}
            calls: list[list[str]] = []

            class Completed:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(argv, **kwargs):
                calls.append(argv)
                return Completed()

            with patch.object(harbor, "docker_argv", side_effect=lambda argv: argv), \
                    patch.object(harbor.subprocess, "run", side_effect=fake_run):
                rebuilt = harbor.rebuild_missing_images(delivery, contract)
            self.assertEqual(rebuilt, [])
            self.assertFalse(any(call[:2] == ["docker", "build"] for call in calls))

    def test_missing_dockerfile_fails_loudly(self):
        with tempfile.TemporaryDirectory() as directory:
            delivery = self.delivery(Path(directory))
            (delivery / "project" / "client" / "Dockerfile").unlink()
            contract = {"images": {"agent": "demo-main:1", "target": "demo-client:1"}}

            class Completed:
                def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
                    self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

            def fake_run(argv, **kwargs):
                if argv[:3] == ["docker", "image", "inspect"]:
                    return Completed(0 if argv[3] == "demo-main:1" else 1)
                return Completed(0)

            with patch.object(harbor, "docker_argv", side_effect=lambda argv: argv), \
                    patch.object(harbor.subprocess, "run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "none of"):
                    harbor.rebuild_missing_images(delivery, contract)


if __name__ == "__main__":
    unittest.main()