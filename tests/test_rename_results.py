from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.rename_results import rename_batch


class RenameResultsTests(unittest.TestCase):
    def test_renames_to_canonical_id_and_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            batch = Path(directory)
            task = batch / "linux-002-cve-2020-28483-gin-gonic-gin"
            (task / "workspace").mkdir(parents=True)
            (task / "workspace/route.json").write_text(json.dumps({
                "instance_id": "CVE-2020-28483::https://github.com/gin-gonic/gin",
                "branch": "SVC-EXPLOIT", "host_type": "synthetic_host"}))
            (task / "result.json").write_text(json.dumps({
                "task_id": task.name,
                "instance_id": "CVE-2020-28483::https://github.com/gin-gonic/gin",
                "status": "passed"}))
            mapping = rename_batch(batch)
            self.assertEqual(mapping, {task.name: "cve-2020-28483-svc-exploit-synthetic-host"})
            renamed = batch / "cve-2020-28483-svc-exploit-synthetic-host"
            self.assertTrue(renamed.is_dir())
            record = json.loads((renamed / "result.json").read_text())
            self.assertEqual(record["task_id"], task.name)
            self.assertEqual(record["folder_name"], renamed.name)
            self.assertTrue((batch / "renames.json").is_file())

    def test_rejected_task_without_branch_becomes_unrouted(self):
        with tempfile.TemporaryDirectory() as directory:
            batch = Path(directory)
            task = batch / "linux-007-cve-2016-10052-imagemagick"
            (task / "workspace").mkdir(parents=True)
            (task / "workspace/route.json").write_text(json.dumps({
                "instance_id": "CVE-2016-10052::https://github.com/imagemagick/imagemagick",
                "branch": None, "host_type": None}))
            (task / "result.json").write_text(json.dumps({
                "task_id": task.name,
                "instance_id": "CVE-2016-10052::https://github.com/imagemagick/imagemagick",
                "status": "rejected"}))
            rename_batch(batch)
            self.assertTrue((batch / "cve-2016-10052-unrouted").is_dir())


if __name__ == "__main__":
    unittest.main()