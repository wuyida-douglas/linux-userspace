from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import resource_cleanup


class ResourceCleanupTests(unittest.TestCase):
    def task(self, directory: Path, images: dict[str, str]) -> Path:
        output = directory / "task"
        (output / "workspace/delivery").mkdir(parents=True)
        (output / "workspace/delivery/task.json").write_text(
            json.dumps({"images": images}), encoding="utf-8")
        return output

    def test_shared_platform_images_are_never_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.task(Path(directory), {
                "agent": "linux-userspace-agent:22.04",
                "target": "demo-client:1",
            })
            self.assertEqual(resource_cleanup._task_images(output), ["demo-client:1"])

    def test_task_images_are_unique_and_ignore_missing_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.task(Path(directory), {"agent": "demo-main:1", "target": "demo-client:1"})
            (output / "harbor/accept-profile/environment").mkdir(parents=True)
            (output / "harbor/accept-profile/environment/task.json").write_text(
                json.dumps({"images": {"agent": "demo-main:1", "target": "demo-client:1"}}),
                encoding="utf-8")
            self.assertEqual(resource_cleanup._task_images(output), ["demo-main:1", "demo-client:1"])

    def test_error_task_releases_images_and_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.task(Path(directory), {"agent": "demo-main:1", "target": "demo-client:1"})
            for relative in ("harbor/bundle", "harbor/accept-profile"):
                (output / relative).mkdir(parents=True)
            calls: list[list[str]] = []

            def fake_run(argv, timeout=0):
                calls.append(argv)
                return resource_cleanup.subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(resource_cleanup, "docker_path", return_value="/usr/bin/docker"), \
                    patch.object(resource_cleanup, "_run", side_effect=fake_run), \
                    patch.object(resource_cleanup, "docker_snapshot",
                                 return_value={"containers": [], "networks": [], "error": None}):
                report = resource_cleanup.cleanup_task(
                    "task", output, {"status": "error", "failure_class": "pipeline"})
            self.assertEqual(report["images"], ["demo-main:1", "demo-client:1"])
            self.assertFalse((output / "harbor/bundle").exists())
            self.assertFalse((output / "harbor/accept-profile").exists())
            self.assertTrue((output / "workspace/delivery/task.json").is_file())

    def test_passed_task_removes_task_images(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.task(Path(directory), {"agent": "demo-main:1", "target": "demo-client:1"})
            calls: list[list[str]] = []

            def fake_run(argv, timeout=0):
                calls.append(argv)
                return resource_cleanup.subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(resource_cleanup, "docker_path", return_value="/usr/bin/docker"), \
                    patch.object(resource_cleanup, "_run", side_effect=fake_run), \
                    patch.object(resource_cleanup, "docker_snapshot",
                                 return_value={"containers": [], "networks": [], "error": None}):
                report = resource_cleanup.cleanup_task("task", output, {"status": "passed"})
            self.assertEqual(report["images"], ["demo-main:1", "demo-client:1"])
            self.assertIn(["/usr/bin/docker", "image", "rm", "--force", "demo-main:1"], calls)

    def test_harbor_failed_also_releases_images(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.task(Path(directory), {"agent": "demo-main:1", "target": "demo-client:1"})
            removed: list[list[str]] = []

            def fake_run(argv, timeout=0):
                removed.append(argv)
                return resource_cleanup.subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(resource_cleanup, "docker_path", return_value="/usr/bin/docker"), \
                    patch.object(resource_cleanup, "_run", side_effect=fake_run), \
                    patch.object(resource_cleanup, "docker_snapshot",
                                 return_value={"containers": [], "networks": [], "error": None}):
                report = resource_cleanup.cleanup_task(
                    "task", output, {"status": "failed", "failure_class": "harbor_failed"})
            self.assertEqual(report["images"], ["demo-main:1", "demo-client:1"])

    def test_forced_cleanup_treats_stopped_in_flight_task_as_finished(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.task(Path(directory), {"agent": "demo-main:1", "target": "demo-client:1"})
            (output / "harbor/bundle").mkdir(parents=True)
            removed: list[list[str]] = []

            def fake_run(argv, timeout=0):
                removed.append(argv)
                return resource_cleanup.subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(resource_cleanup, "docker_path", return_value="/usr/bin/docker"), \
                    patch.object(resource_cleanup, "_run", side_effect=fake_run), \
                    patch.object(resource_cleanup, "docker_snapshot",
                                 return_value={"containers": [], "networks": [], "error": None}):
                report = resource_cleanup.cleanup_task("task", output, {"status": "harbor"},
                                                       force=True)
            self.assertTrue(report["finished"])
            self.assertEqual(report["images"], ["demo-main:1", "demo-client:1"])
            self.assertFalse((output / "harbor/bundle").exists())

    def test_in_flight_task_keeps_everything(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.task(Path(directory), {"agent": "demo-main:1", "target": "demo-client:1"})
            (output / "harbor/bundle").mkdir(parents=True)
            with patch.object(resource_cleanup, "docker_path", return_value=None):
                report = resource_cleanup.cleanup_task("task", output, {"status": "harbor"})
            self.assertFalse(report["finished"])
            self.assertTrue((output / "harbor/bundle").is_dir())


if __name__ == "__main__":
    unittest.main()

class SweepTests(unittest.TestCase):
    def test_idle_volumes_are_attributed_by_label_or_dangling_age(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "results"
            root.mkdir()
            listing = (f"dbdata\t{root}/task/harbor/acc/environment\n"
                       f"hub\t/somewhere/else\n"
                       f"anon\t\n")
            calls = []

            def fake_run(argv, timeout=0):
                calls.append(argv)

                class Result:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                if argv[1] == "volume" and argv[2] == "ls" and "dangling=true" in argv:
                    Result.stdout = "anon\n"
                elif argv[1] == "volume" and argv[2] == "ls":
                    Result.stdout = listing
                elif argv[1] == "volume" and argv[2] == "inspect":
                    # dbdata and anon are old; hub is not selected at all.
                    Result.stdout = "2020-01-01T00:00:00Z"
                elif argv[1] == "volume" and argv[2] == "rm":
                    Result.stdout = argv[3]
                return Result()

            with patch.object(resource_cleanup, "_run", side_effect=fake_run), \
                    patch.object(resource_cleanup, "docker_path", return_value="/usr/bin/docker"):
                report = resource_cleanup.prune_idle_volumes(root)
            self.assertEqual(report["volumes"], 2)
            self.assertEqual(report["removed"], 2)
            removed = [call[3] for call in calls if call[1:3] == ["volume", "rm"]]
            self.assertEqual(sorted(removed), ["anon", "dbdata"])

    def test_stale_image_sweep_keeps_protected_and_recent_images(self):
        with tempfile.TemporaryDirectory() as directory:
            old = "2020-01-01 00:00:00 +0000 UTC"
            listing = (f"sha256:a\tlinux-userspace-agent:22.04\t{old}\n"
                       f"sha256:b\tdemo-main:1\t{old}\n"
                       f"sha256:c\tdemo-fresh:1\t2099-01-01 00:00:00 +0000 UTC\n")
            removed = []

            def fake_run(argv, timeout=0):
                class Result:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                if argv[1] == "images":
                    Result.stdout = listing
                elif argv[1] == "image" and argv[2] == "rm":
                    removed.extend(argv[3:])
                    Result.stdout = "deleted\n"
                return Result()

            with patch.object(resource_cleanup, "_run", side_effect=fake_run), \
                    patch.object(resource_cleanup, "docker_path", return_value="/usr/bin/docker"):
                report = resource_cleanup.prune_stale_images(min_age_hours=12)
            self.assertEqual(report["images"], 1)
            self.assertIn("sha256:b", removed)
            self.assertNotIn("sha256:a", removed)
            self.assertNotIn("sha256:c", removed)
