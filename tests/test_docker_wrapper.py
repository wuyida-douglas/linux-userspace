from __future__ import annotations

import importlib.util
import os
from importlib.machinery import SourceFileLoader
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

WRAPPER = Path(__file__).resolve().parents[1] / "config/bin/docker"


def load_wrapper(workspace: Path):
    loader = SourceFileLoader("docker_wrapper_test", str(WRAPPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DockerWrapperTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "results/batch/task/workspace"
        self.ws.mkdir(parents=True)
        self.env = patch.dict(os.environ, {
            "AGENT_GUARD_WORKSPACE": str(self.ws),
            "COMPOSE_PROJECT_NAME": "proj-test",
        })
        self.env.start()
        self.module = load_wrapper(self.ws)

    def tearDown(self):
        self.env.stop()
        self._tmp.cleanup()

    def test_target_parsing_skips_options(self):
        self.assertEqual(self.module._container_targets(["stop", "-t", "5", "abc"]), ["abc"])
        self.assertEqual(self.module._container_targets(["rm", "-f", "-v", "a", "b"]), ["a", "b"])
        self.assertEqual(
            self.module._container_targets(["exec", "-u", "root", "-e", "A=B", "ctr", "echo"]),
            ["ctr"])
        self.assertEqual(self.module._container_targets(["cp", "./x", "ctr:/y"]), ["ctr"])

    def test_owned_accepts_task_label_and_compose_workdir(self):
        self.assertTrue(self.module._owned({"pipeline.task": "task"}))
        self.assertTrue(self.module._owned({
            "com.docker.compose.project.working_dir": str(self.ws / "delivery/environment")}))
        self.assertFalse(self.module._owned({"pipeline.task": "other"}))
        self.assertFalse(self.module._owned({}))

    def test_guard_refuses_global_prune(self):
        with self.assertRaises(SystemExit) as raised:
            self.module._guard_argv(["system", "prune", "-af"])
        self.assertEqual(raised.exception.code, 2)

    def test_guard_checks_owned_targets(self):
        with patch.object(self.module, "_inspect_labels", return_value={"pipeline.task": "task"}):
            self.assertEqual(self.module._guard_argv(["kill", "abc"]), ["kill", "abc"])
        with patch.object(self.module, "_inspect_labels", return_value={"pipeline.task": "other"}):
            with self.assertRaises(SystemExit):
                self.module._guard_argv(["kill", "abc"])

    def test_run_gets_ownership_label(self):
        argv = self.module._guard_argv(["run", "--rm", "alpine", "true"])
        self.assertIn("--label", argv)
        self.assertIn("pipeline.task=task", argv)

    def test_compose_path_outside_task_is_refused(self):
        with self.assertRaises(SystemExit):
            self.module._guard_argv(["compose", "-f", str(self.root / "other/docker-compose.yaml"), "down"])


if __name__ == "__main__":
    unittest.main()
