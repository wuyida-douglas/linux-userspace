from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from pipeline import docker_ipam


class IpamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"PIPELINE_IPAM_STATE": str(self.root / "state"),
                                           "PIPELINE_IPAM_WORK_DIR": str(self.root / "runtime")})
        self.env.start()
        self.occupied = [ipaddress.ip_network("10.80.0.0/24"),
                         ipaddress.ip_network("10.112.0.0/24")]

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def allocate(self, requested, project, role):
        with patch.object(docker_ipam, "_docker_networks", return_value=self.occupied), \
                patch.object(docker_ipam, "_network_subnet", return_value=""):
            return docker_ipam._allocate(requested, project, role, "docker-test")

    def test_network_disappearing_between_list_and_inspect_is_absent(self):
        def run(argv, **kwargs):
            if argv[1:3] == ["network", "ls"]:
                return subprocess.CompletedProcess(argv, 0, "gone\nlive\n", "")
            if argv[3] == "gone":
                return subprocess.CompletedProcess(argv, 1, "", "Error response from daemon: network gone not found")
            return subprocess.CompletedProcess(argv, 0, "10.80.0.0/24 ", "")
        with patch.object(docker_ipam.subprocess, "run", side_effect=run) as execute:
            self.assertEqual(docker_ipam._docker_networks("docker-test"), self.occupied[:1])
            self.assertEqual(execute.call_count, 3)

    def test_real_network_inspection_error_is_not_suppressed(self):
        def run(argv, **kwargs):
            if argv[1:3] == ["network", "ls"]:
                return subprocess.CompletedProcess(argv, 0, "live\n", "")
            return subprocess.CompletedProcess(argv, 1, "", "permission denied")
        with patch.object(docker_ipam.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                docker_ipam._docker_networks("docker-test")

    def test_disjoint_pools_skip_live_subnets_and_reuse_project(self):
        factory = self.allocate({"default": "factory-a_default"}, "factory-a", "factory")
        harbor = self.allocate({"default": "harbor-a_default"}, "harbor-a", "harbor")
        self.assertEqual(factory, {"default": "10.80.1.0/24"})
        self.assertEqual(harbor, {"default": "10.112.1.0/24"})
        self.assertEqual(self.allocate({"default": "factory-a_default"}, "factory-a", "factory"), factory)
        self.assertEqual(self.allocate({"default": "factory-b_default"}, "factory-b", "factory"),
                         {"default": "10.80.2.0/24"})

    def test_concurrent_projects_never_receive_same_subnet(self):
        with patch.object(docker_ipam, "_docker_networks", return_value=self.occupied), \
                patch.object(docker_ipam, "_network_subnet", return_value=""), \
                concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda index: docker_ipam._allocate(
                {"default": f"concurrent-{index}_default"}, f"concurrent-{index}", "factory", "docker-test"), range(40)))
        subnets = [value["default"] for value in results]
        self.assertEqual(len(set(subnets)), len(subnets))
        for subnet in subnets:
            self.assertFalse(any(ipaddress.ip_network(subnet).overlaps(other) for other in self.occupied))

    def test_explicit_default_and_named_networks_are_managed(self):
        (self.root / "compose.yaml").write_text(yaml.safe_dump({
            "services": {"client": {"image": "target:1", "networks": ["default", "backend"]}},
            "networks": {"backend": {}}}))
        with patch.object(docker_ipam, "_allocate", return_value={"default": "10.80.2.0/24",
                                                                  "backend": "10.80.3.0/24"}) as allocate:
            argv = docker_ipam.inject_compose_ipam(
                ["compose", "-f", "compose.yaml", "up", "-d"], self.root, "docker-test")
            project = self.root.name.lower()
            self.assertEqual(allocate.call_args.args[0],
                             {"default": project + "_default", "backend": project + "_backend"})
        self.assertEqual(argv[0], "compose")
        override = str(self.root / "runtime/backend-default.yaml")
        override_index = argv.index(override)
        self.assertEqual(argv[override_index - 1], "-f")
        self.assertGreater(override_index, argv.index("compose.yaml"))
        self.assertLess(override_index, argv.index("up"))
        value = yaml.safe_load(Path(override).read_text())
        self.assertEqual(value["networks"]["backend"]["ipam"]["config"][0]["subnet"], "10.80.3.0/24")
        # Docker Compose 2.40 requires service names in a late override.
        # Empty mappings avoid appending security_opt and cap_add twice.
        self.assertEqual(value["services"], {"client": {}})
        self.assertFalse((self.root / ".compose-ipam").exists())

    def test_override_precedes_up_after_original_file(self):
        (self.root / "other.yaml").write_text("services:\n  client:\n    image: target:1\n")
        with patch.object(docker_ipam, "_allocate", return_value={"default": "10.80.2.0/24"}):
            result = docker_ipam.inject_compose_ipam(
                ["compose", "--project-name", "example", "-f", "other.yaml", "up", "-d"],
                self.root, "docker-test")
        self.assertEqual(result[0], "compose")
        override = str(self.root / "runtime/default.yaml")
        override_index = result.index(override)
        self.assertEqual(result[override_index - 1], "-f")
        self.assertGreater(override_index, result.index("other.yaml"))
        self.assertLess(override_index, result.index("up"))
        self.assertIn("other.yaml", result)

    def test_static_address_external_and_application_ipam_are_not_rewritten(self):
        value = {"services": {"client": {"image": "target:1", "networks": {
                    "app": {"ipv4_address": "10.200.1.4"},
                    "external": None}}},
                 "networks": {"app": {"ipam": {"config": [{"subnet": "10.200.1.0/24"}]}},
                              "external": {"external": True}}}
        (self.root / "compose.yaml").write_text(yaml.safe_dump(value))
        self.assertEqual(docker_ipam._requested_networks(["compose", "up"], self.root), {})
        self.assertFalse(docker_ipam.inject_compose_ipam(
            ["compose", "up"], self.root, "docker-test") != ["compose", "up"])

    def test_config_down_and_disabled_do_not_allocate(self):
        (self.root / "compose.yaml").write_text("services:\n  client:\n    image: target:1\n")
        for command in ("config", "down"):
            argv = ["compose", command]
            self.assertEqual(docker_ipam.inject_compose_ipam(argv, self.root, "docker-test"), argv)
        with patch.dict(os.environ, {"PIPELINE_IPAM_DISABLE": "1"}):
            argv = ["compose", "up"]
            self.assertEqual(docker_ipam.inject_compose_ipam(argv, self.root, "docker-test"), argv)

    def test_recreate_reassigns_lease_when_its_subnet_was_taken(self):
        first = self.allocate({"default": "recreate_default"}, "recreate", "factory")["default"]
        self.occupied.append(ipaddress.ip_network(first))
        second = self.allocate({"default": "recreate_default"}, "recreate", "factory")["default"]
        self.assertNotEqual(first, second)

    def test_release_only_after_project_network_disappears(self):
        allocated = self.allocate({"default": "release-a_default"}, "release-a", "harbor")
        subnet = allocated["default"]
        with patch.object(docker_ipam, "_network_subnet", return_value=subnet):
            self.assertEqual(docker_ipam.release_compose_subnets("release-a", "harbor", "docker-test"), [])
        with patch.object(docker_ipam, "_network_subnet", return_value=""):
            self.assertEqual(docker_ipam.release_compose_subnets("release-a", "harbor", "docker-test"), [subnet])
        self.assertEqual(json.loads((self.root / "state/leases.json").read_text()), {})


if __name__ == "__main__":
    unittest.main()
