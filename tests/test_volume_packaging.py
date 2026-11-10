from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from pipeline import package_volumes, pristine_binds


class VolumePackageTests(unittest.TestCase):
    def test_detects_named_and_anonymous_but_not_bind(self):
        compose = {"services": {"client": {"volumes": [
            "dbdata:/var/lib/mysql", "./assets:/assets:ro", "/anon"]}}}
        self.assertTrue(package_volumes.compose_has_named_volumes(compose))
        compose["services"]["client"]["volumes"] = ["./assets:/assets:ro"]
        self.assertFalse(package_volumes.compose_has_named_volumes(compose))

    def test_rewrites_named_volume_to_packaged_bind(self):
        compose = {
            "services": {"client": {"volumes": ["dbdata:/var/lib/mysql"]}},
            "volumes": {"dbdata": {}},
        }
        rows = [{"service": "client", "destination": "/var/lib/mysql",
                 "rel": "init/volumes/dbdata", "volume": "dbdata"}]
        package_volumes.apply_volume_package(compose, rows)
        self.assertEqual(compose["services"]["client"]["volumes"],
                         ["./init/volumes/dbdata:/var/lib/mysql"])
        self.assertNotIn("volumes", compose)

    def test_adds_bind_for_image_declared_volume(self):
        compose = {"services": {"client": {"volumes": ["./assets:/assets:ro"]}}}
        rows = [{"service": "client", "destination": "/var/lib/mysql",
                 "rel": "init/volumes/dbdata", "volume": "dbdata"}]
        package_volumes.apply_volume_package(compose, rows)
        self.assertIn("./init/volumes/dbdata:/var/lib/mysql",
                      compose["services"]["client"]["volumes"])

    def test_bind_rel_is_safe(self):
        self.assertEqual(package_volumes.bind_rel("../../x y", "/data"),
                         "init/volumes/x-y")

    def test_packaging_is_branch_agnostic_for_main_client_sidecar(self):
        for services in (
            {"main": {"image": "agent:1"}, "client": {"volumes": ["dbdata:/data"]}},
            {"main": {"image": "agent:1"}, "client": {"volumes": ["dbdata:/data"]},
             "db": {"volumes": ["dbdata:/var/lib/db"]}},
        ):
            compose = {"services": services, "volumes": {"dbdata": {}}}
            rows = [{"service": name, "destination": target,
                     "rel": f"init/volumes/{name}", "volume": "dbdata"}
                    for name, service in services.items() if name != "main"
                    for target in [v.split(":")[1] for v in service.get("volumes", [])]]
            package_volumes.apply_volume_package(compose, rows)
            for name, service in services.items():
                if name == "main":
                    continue
                self.assertTrue(all(str(item).startswith("./init/volumes/")
                                    for item in service["volumes"]))


class PristineBindTests(unittest.TestCase):
    def test_writable_rels_skip_readonly_and_collapse_nested(self):
        compose = {"services": {"client": {"volumes": [
            "./init:/init", "./init/volumes/db:/var/lib/mysql",
            "./assets:/assets:ro"]}}}
        self.assertEqual(pristine_binds.writable_bind_rels(compose), ["init"])

    def test_archive_restores_writable_bind(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory)
            environment = task / "environment"
            data = environment / "init/volumes/db"
            data.mkdir(parents=True)
            (data / "row.txt").write_text("planted\n")
            (environment / "docker-compose.yaml").write_text(yaml.safe_dump({
                "services": {"client": {"volumes": [
                    "./init/volumes/db:/var/lib/mysql"]}}}))
            archive = pristine_binds.create_pristine_binds_tar(task)
            self.assertIsNotNone(archive)
            (data / "row.txt").write_text("attacker changed\n")
            (data / "extra.txt").write_text("extra\n")
            self.assertTrue(pristine_binds.extract_pristine_binds(task, environment))
            self.assertEqual((data / "row.txt").read_text(), "planted\n")
            self.assertFalse((data / "extra.txt").exists())


if __name__ == "__main__":
    unittest.main()