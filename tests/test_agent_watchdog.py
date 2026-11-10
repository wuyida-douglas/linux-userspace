from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from pipeline import agent


class AgentResultWatchdogTests(unittest.TestCase):
    def test_final_result_terminates_a_hanging_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "fake-claude"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json, time\n"
                "print(json.dumps({'type': 'result', 'is_error': False, "
                "'subtype': 'success', 'num_turns': 1}), flush=True)\n"
                "time.sleep(60)\n")
            fake.chmod(0o755)
            previous = os.environ.get("CLAUDE_BIN")
            os.environ["CLAUDE_BIN"] = str(fake)
            self.addCleanup(lambda: os.environ.__setitem__("CLAUDE_BIN", previous)
                            if previous is not None else os.environ.pop("CLAUDE_BIN", None))
            workspace = root / "workspace"
            workspace.mkdir()
            started = time.monotonic()
            record = agent.run("prompt", workspace, root / "out", model="test",
                               credentials={}, max_turns=1, timeout=30,
                               network=root)
            elapsed = time.monotonic() - started
            self.assertEqual(record["status"], "completed", record)
            self.assertLess(elapsed, 20)
            self.assertTrue((root / "out/trajectory.jsonl").is_file())


class CompactLogTests(unittest.TestCase):
    def test_logs_keep_thinking_and_use_beijing_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            events = [
                {"type": "system", "subtype": "thinking_tokens",
                 "timestamp": "2026-11-09T17:07:53.000Z", "estimated_tokens": 1},
                {"type": "assistant", "timestamp": "2026-11-09T17:07:54.275Z",
                 "message": {"id": "msg1", "content": [
                     {"type": "thinking", "thinking": "huge private thought"}]}},
                {"type": "assistant", "timestamp": "2026-11-09T17:07:54.634Z",
                 "message": {"id": "msg1", "content": [
                     {"type": "text", "text": "I will inspect the file."},
                     {"type": "tool_use", "id": "t1", "name": "Bash",
                      "input": {"command": "ls -la", "description": "List files"}}]}},
                {"type": "user", "timestamp": "2026-11-09T17:07:54.700Z",
                 "message": {"content": [
                     {"type": "tool_result", "tool_use_id": "t1",
                      "content": [{"type": "text", "text": "total 0"}]}]}},
                {"type": "assistant", "timestamp": "2026-11-09T17:08:07.133Z",
                 "message": {"id": "msg2", "content": [
                     {"type": "thinking", "thinking": "thinking-only turn"}]}},
                {"type": "system", "subtype": "compact_boundary",
                 "timestamp": "2026-11-09T17:08:08.000Z",
                 "compact_metadata": {"trigger": "auto"}},
                {"type": "result", "timestamp": "2026-11-09T17:08:09.000Z",
                 "is_error": False, "subtype": "success", "num_turns": 2, "result": "done"},
            ]
            with (output / "stdout.jsonl").open("w") as handle:
                for event in events:
                    handle.write(json.dumps(event) + "\n")
            result = agent._write_compact_logs(output)
            self.assertEqual(result["subtype"], "success")
            trajectory = [json.loads(line) for line in
                          (output / "trajectory.jsonl").read_text().splitlines()]
            self.assertEqual([item["type"] for item in trajectory],
                             ["assistant", "tool_result", "assistant", "system", "result"])
            self.assertEqual(trajectory[0]["turn"], 1)
            self.assertEqual(trajectory[2]["turn"], 2)
            self.assertEqual(trajectory[0]["tools"], ["Bash"])
            self.assertNotIn("huge private thought", json.dumps(trajectory))
            self.assertEqual(trajectory[3]["type"], "system")
            self.assertFalse((output / "conversation.md").exists())
            calls = [json.loads(line) for line in
                     (output / "tool-calls.jsonl").read_text().splitlines()]
            self.assertEqual(list(calls[0])[0], "time")
            self.assertEqual(calls[0]["time"], "2026-11-10 01:07:54.634 +0800")
            self.assertEqual(calls[0]["description"], "List files")
            self.assertNotIn("description", calls[0]["input"])
            self.assertIn("ls -la", calls[0]["input"]["command"])
            live = (output / "live.chat.md").read_text()
            self.assertIn("total 0", live)
            self.assertIn("huge private thought", live)
            self.assertIn("thinking-only turn", live)
            self.assertIn("Claude Code compaction", live)
            self.assertIn("List files", live)
            sft = json.loads((output / "sft.jsonl").read_text())
            self.assertTrue(any(block.get("type") == "thinking"
                                for message in sft["messages"]
                                if isinstance(message.get("content"), list)
                                for block in message["content"]
                                if isinstance(block, dict)))
            self.assertTrue(any(message.get("event") == "compact_boundary"
                                for message in sft["messages"]))

    def test_autocompact_keeps_pre_compact_history_and_string_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            long_result = "final-" + "x" * 30000
            events = [
                {"type": "assistant", "timestamp": "2026-11-10T01:00:00.000Z",
                 "message": {"id": "before", "content": [
                     {"type": "text", "text": "BEFORE_COMPACT"}]}},
                {"type": "system", "subtype": "compact_boundary",
                 "timestamp": "2026-11-10T01:00:01.000Z"},
                {"type": "user", "timestamp": "2026-11-10T01:00:02.000Z",
                 "isCompactSummary": True,
                 "message": {"role": "user", "content": "COMPACT_SUMMARY_TEXT"}},
                {"type": "assistant", "timestamp": "2026-11-10T01:00:03.000Z",
                 "message": {"id": "after", "content": [
                     {"type": "text", "text": "AFTER_COMPACT"}]}},
                {"type": "result", "timestamp": "2026-11-10T01:00:04.000Z",
                 "is_error": False, "subtype": "success", "num_turns": 2,
                 "result": long_result},
            ]
            with (output / "stdout.jsonl").open("w") as handle:
                for event in events:
                    handle.write(json.dumps(event) + "\n")
            agent._write_compact_logs(output)
            live = (output / "live.chat.md").read_text()
            self.assertIn("BEFORE_COMPACT", live)
            self.assertIn("AFTER_COMPACT", live)
            self.assertIn("COMPACT_SUMMARY_TEXT", live)
            self.assertIn("Claude Code compaction", live)
            sft = json.loads((output / "sft.jsonl").read_text())
            text = "\n".join(
                str(message.get("content", "")) for message in sft["messages"])
            self.assertIn("BEFORE_COMPACT", text)
            self.assertIn("AFTER_COMPACT", text)
            self.assertIn("COMPACT_SUMMARY_TEXT", text)
            self.assertEqual(sft["metadata"]["result"]["result"], long_result)

    def test_background_task_output_is_archived(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            source = output / "task-output.txt"
            source.write_text("background detail\n")
            events = [
                {"type": "system", "subtype": "task_notification",
                 "timestamp": "2026-11-10T01:00:00.000Z",
                 "task_id": "task-1", "output_file": str(source)},
                {"type": "result", "is_error": False, "subtype": "success",
                 "num_turns": 0, "result": "done"},
            ]
            with (output / "stdout.jsonl").open("w") as handle:
                for event in events:
                    handle.write(json.dumps(event) + "\n")
            agent._write_compact_logs(output)
            archived = output / "background/task-output.txt"
            self.assertEqual(archived.read_text(), "background detail\n")
            manifest = json.loads((output / "background-tasks.jsonl").read_text())
            self.assertEqual(manifest["archived"], "background/task-output.txt")


if __name__ == "__main__":
    unittest.main()