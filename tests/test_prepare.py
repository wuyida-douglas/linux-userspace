from __future__ import annotations

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from pipeline import common, prepare


class NamingTests(unittest.TestCase):
    def test_task_id_uses_cve_and_owner_repo_without_clone_url(self):
        row = {"instance_id": "CVE-2024-23346::https://github.com/materialsproject/pymatgen",
               "canonical_id": "CVE-2024-23346",
               "repo": "https://github.com/materialsproject/pymatgen.git"}
        self.assertEqual(common.task_id(row, 14),
                         "linux-014-cve-2024-23346-materialsproject-pymatgen")
        same_name = {"instance_id": "CVE-2022-0326::https://github.com/mruby/mruby",
                     "canonical_id": "CVE-2022-0326",
                     "repo": "https://github.com/mruby/mruby.git"}
        self.assertEqual(common.task_id(same_name, 1), "linux-001-cve-2022-0326-mruby")

    def test_export_task_id_appends_branch_and_svc_host_type(self):
        task = "linux-001-cve-2020-28483-gin-gonic-gin"
        self.assertEqual(
            common.export_task_id(task, "SVC-EXPLOIT", "synthetic_host"),
            "cve-2020-28483-svc-exploit-synthetic-host")
        self.assertEqual(common.export_task_id(task, "FILE-POV", None),
                         "cve-2020-28483-file-pov")

    def test_s3_canonical_id_normalizes_ghsa_advisory_case(self):
        self.assertEqual(prepare.s3_canonical_id("GHSA-7CWM-FPFH-RRCH"),
                         "GHSA-7cwm-fpfh-rrch")
        self.assertEqual(prepare.s3_canonical_id("CVE-2024-23346"), "CVE-2024-23346")
        self.assertEqual(prepare.s3_canonical_id("OSV-2020-317"), "OSV-2020-317")

    def test_s3_alias_index_maps_vendor_cve_directories(self):
        listing = ("circl_cve_CVE-2024-0001/\n"
                   "osv_UBUNTU-CVE-2024-0001/\n"
                   "osv_DEBIAN-CVE-2024-0002/\n"
                   "osv_CVE-2024-0003/\n"
                   "cvelist_CVE-2024-0003/\n")
        completed = unittest.mock.Mock(returncode=0, stdout=listing)
        with unittest.mock.patch.object(prepare.subprocess, "run", return_value=completed):
            aliases = prepare.s3_alias_index("remote:path")
        self.assertEqual(aliases["CVE-2024-0001"], ["osv_UBUNTU-CVE-2024-0001"])
        self.assertEqual(aliases["CVE-2024-0002"], ["osv_DEBIAN-CVE-2024-0002"])
        self.assertNotIn("CVE-2024-0003", aliases)

    def test_export_task_id_cleans_legacy_url_and_stays_bounded(self):
        legacy = "linux-009-osv-2020-177-https-github-com-ntop-ndpi"
        cleaned = common.export_task_id(legacy, "SVC-EXPLOIT", "real_host")
        self.assertEqual(cleaned, "osv-2020-177-svc-exploit-real-host")
        long = common.export_task_id("linux-001-" + "a" * 200, "FILE-EXPLOIT", None)
        self.assertLessEqual(len(long), 160)
        self.assertTrue(long.endswith("-file-exploit"))


class FullPoolTests(unittest.TestCase):
    def test_sample_all_preserves_pool_order(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = Path(directory) / "pool.jsonl"
            rows = [
                {"instance_id": "CVE-b::https://github.com/o/b", "canonical_id": "CVE-b",
                 "repo": "https://github.com/o/b", "vulnerability": {}, "code": {}, "old_tags": {}},
                {"instance_id": "CVE-a::https://github.com/o/a", "canonical_id": "CVE-a",
                 "repo": "https://github.com/o/a", "vulnerability": {}, "code": {}, "old_tags": {}},
            ]
            pool.write_text("".join(json.dumps(row) + "\n" for row in rows))
            selected = prepare.sample_all(pool)
            self.assertEqual([row["instance_id"] for row in selected],
                             ["CVE-b::https://github.com/o/b", "CVE-a::https://github.com/o/a"])
            self.assertEqual([row["sample_id"] for row in selected], [1, 2])


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

    def test_ghsa_snapshot_uses_mirror_uppercase_prefix_and_lowercase_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote"
            candidate = remote / "osv_GHSA-7cwm-fpfh-rrch/candidates/candidate-1"
            candidate.joinpath("prefix").mkdir(parents=True)
            candidate.joinpath("prefix/module.py").write_text("vulnerable = True\n")
            candidate.joinpath("fix.diff").write_text(
                "diff --git a/module.py b/module.py\n--- a/module.py\n+++ b/module.py\n")
            remote.joinpath("osv_GHSA-7cwm-fpfh-rrch/meta.json").write_text(json.dumps({
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
            row = self.row() | {"canonical_id": "GHSA-7CWM-FPFH-RRCH"}
            with unittest.mock.patch.object(prepare, "copy", side_effect=local_copy):
                result = prepare.prepare_one(row, root / "output", str(remote))
            self.assertEqual(result["status"], "complete", result)

    def test_vendor_alias_snapshot_is_used_when_the_bare_cve_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote"
            candidate = remote / "osv_UBUNTU-CVE-2024-0001/candidates/candidate-1"
            candidate.joinpath("prefix").mkdir(parents=True)
            candidate.joinpath("prefix/module.py").write_text("vulnerable = True\n")
            candidate.joinpath("fix.diff").write_text(
                "diff --git a/module.py b/module.py\n--- a/module.py\n+++ b/module.py\n")
            remote.joinpath("osv_UBUNTU-CVE-2024-0001/meta.json").write_text(json.dumps({
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
            row = self.row() | {"canonical_id": "CVE-2024-0001"}
            aliases = {"CVE-2024-0001": ["osv_UBUNTU-CVE-2024-0001"]}
            with unittest.mock.patch.object(prepare, "copy", side_effect=local_copy):
                result = prepare.prepare_one(row, root / "output", str(remote), aliases=aliases)
            self.assertEqual(result["status"], "complete", result)
            meta = json.loads((root / "output/linux-001/input/meta.json").read_text())
            self.assertEqual(meta["source"], "osv")
            self.assertEqual(meta["source_path"], "osv_UBUNTU-CVE-2024-0001")

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
