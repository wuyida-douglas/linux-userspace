from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "config/bin/agent_guard.py"


class AgentGuardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.task = self.root / "results/iterate-current/batch-001/task"
        self.ws = self.task / "workspace"
        self.ws.mkdir(parents=True)
        (self.task / "route").mkdir()
        (self.task / "route/live.chat.md").write_text("route")
        (self.ws / "input").mkdir()
        (self.ws / "input/fix.diff").write_text("diff")
        self.prior = self.root / "results/iterate-prior/batch-001/task/workspace"
        self.prior.mkdir(parents=True)
        (self.prior / "delivery").mkdir()
        (self.root / "env").write_text("ANTHROPIC_AUTH_TOKEN=<redacted>\n")
        (self.root / "pipeline").mkdir()
        (self.root / "pipeline/pass2fail_verifier.py").write_text("# verifier\n")
        (self.root / "config/bin").mkdir(parents=True)
        (self.root / "config/bin/docker").write_text("# docker\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, tool: str, tool_input: dict) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env.update({
            "AGENT_GUARD_ROOT": str(self.root),
            "AGENT_GUARD_WORKSPACE": str(self.ws),
            "AGENT_GUARD_LOG": str(self.root / "guard.log"),
        })
        return subprocess.run(
            [sys.executable, str(GUARD)],
            input=json.dumps({"tool_name": tool, "tool_input": tool_input}),
            text=True, capture_output=True, env=env)

    def test_blocks_memory_and_prior_runs(self):
        cases = [
            ("Bash", {"command": "cat /home/wuyida/.claude/projects/x/memory/MEMORY.md"}),
            ("Bash", {"command": f"cp -a {self.prior}/delivery ."}),
            ("Bash", {"command": "cp -a results/iterate-prior/batch-001/task/workspace/delivery ."}),
            ("Bash", {"command": f"cat {self.root}/env"}),
            ("Bash", {"command": f"find {self.root} -maxdepth 2"}),
            ("Bash", {"command": f"find {self.root}/ -maxdepth 2"}),
            ("Bash", {"command": f"ls {self.root}/results"}),
            ("Bash", {"command": f"ls {self.root}/results/"}),
            ("Bash", {"command": "docker run -v /home/wuyida/.claude:/x alpine true"}),
            ("Read", {"file_path": str(self.prior / "delivery/task.json")}),
            ("Read", {"file_path": "/home/wuyida/.claude/projects/x/memory/MEMORY.md"}),
            ("Read", {"file_path": str(self.root / "env")}),
            ("Write", {"file_path": str(self.task / "synthesis/x")}),
            ("Bash", {"command": f"ls {self.root}/pipeline"}),
            ("Bash", {"command": f"cat {self.root}/config/bin/docker"}),
            ("Read", {"file_path": str(self.root / "pipeline/pass2fail_verifier.py")}),
            ("Bash", {"command": "docker kill $(docker ps -q)"}),
            ("Bash", {"command": "docker rm -f $(docker ps -aq)"}),
            ("Bash", {"command": "docker system prune -af"}),
            ("Bash", {"command": "cat /tmp/linux-userspace-ipam-1/leases.json"}),
            ("Write", {"file_path": "/tmp/linux-userspace-ipam-1/leases.json"}),
            ("Bash", {"command": "cat /home/wuyida/other/notes"}),
        ]
        for tool, tool_input in cases:
            with self.subTest(tool=tool, input=tool_input):
                result = self._run(tool, tool_input)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_allows_workspace_and_current_task_stage_outputs(self):
        cases = [
            ("Bash", {"command": f"cat {self.ws}/input/fix.diff"}),
            ("Bash", {"command": f"cat {self.task}/route/live.chat.md"}),
            ("Bash", {"command": f"ls {self.task}/route"}),
            ("Bash", {"command": "docker rm -f $(docker ps -aq --filter ancestor=fli-dev:1)"}),
            ("Bash", {"command": "cat /nvme/wuyida/tmp/claude-abc/tasks/x.output"}),
            ("Bash", {"command": "docker run -v \"$PWD\":/m alpine true"}),
            ("Bash", {"command": "echo ok"}),
            ("Read", {"file_path": str(self.ws / "input/fix.diff")}),
            ("Read", {"file_path": str(self.task / "route/live.chat.md")}),
            ("Read", {"file_path": "/nvme/wuyida/tmp/claude-abc/tasks/x.output"}),
            ("Write", {"file_path": str(self.ws / "delivery/task.json")}),
            ("Write", {"file_path": "/tmp/scratch.txt"}),
        ]
        for tool, tool_input in cases:
            with self.subTest(tool=tool, input=tool_input):
                result = self._run(tool, tool_input)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_unparsable_payload_fails_open(self):
        result = subprocess.run(
            [sys.executable, str(GUARD)], input="not json", text=True,
            capture_output=True,
            env=dict(os.environ, AGENT_GUARD_ROOT=str(self.root),
                     AGENT_GUARD_WORKSPACE=str(self.ws)))
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()