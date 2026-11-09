from __future__ import annotations

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from pipeline import prepare


class InputDownloadTests(unittest.TestCase):
    def row(self):
        return {
            "sample_id": 1, "task_id": "linux-001", "canonical_id": "CVE-test",
            "instance_id": "CVE-test::project", "candidate_id": "candidate-1",
            "repo": "https://example.invalid/project", "source_hint": "osv",
            "vulnerability": {}, "code": {}, "old_tags": {},
        }

    def test_moved_patch_is_counted_in_the_final_input_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote"
            candidate = remote / "osv_CVE-test/candidates/candidate-1"
            candidate.joinpath("prefix").mkdir(parents=True)
            candidate.joinpath("prefix/module.py").write_text("vulnerable = True\n")
            candidate.joinpath("fix.diff").write_text(
                "diff --git a/module.py b/module.py\n--- a/module.py\n+++ b/module.py\n")
            remote.joinpath("osv_CVE-test/meta.json").write_text(json.dumps({
                "code": {"candidates": [{"candidate_id": "candidate-1"}]}}))
            def local_copy(remote: str, destination: Path, **kwargs):
                source = Path(remote)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if kwargs.get("directory"):
                    import shutil
                    shutil.copytree(source, destination)
                else:
                    import shutil
                    shutil.copy2(source, destination)
            with unittest.mock.patch.object(prepare, "copy", side_effect=local_copy):
                result = prepare.prepare_one(self.row(), root / "output", str(remote))
            self.assertEqual(result["status"], "complete", result)
            manifest = json.loads((root / "output/linux-001/input/manifest.json").read_text())
            self.assertEqual(manifest["errors"], [])
            self.assertIn("fix.diff", manifest["files"])

    def test_missing_object_does_not_leave_an_empty_download(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested/fix.diff"
            with unittest.mock.patch.object(prepare.subprocess, "run") as run:
                run.return_value.returncode = 1
                run.return_value.stdout = ""
                run.return_value.stderr = "object not found"
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    prepare.copy("p_huawei_hdd1:bucket/missing-object", destination)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
