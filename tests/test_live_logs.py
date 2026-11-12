from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from pipeline.agent import LiveLogs, _write_compact_logs


def event(value: dict) -> str:
    return json.dumps(value)


class LiveLogsTests(unittest.TestCase):
    def test_tool_calls_and_chat_are_written_before_the_session_ends(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            stdout = output / "stdout.jsonl"
            first = [
                {"type": "system", "subtype": "init",
                 "timestamp": "2026-11-11T10:00:00Z", "session_id": "s1"},
                {"type": "assistant", "timestamp": "2026-11-11T10:00:01Z",
                 "message": {"id": "m1", "content": [
                     {"type": "thinking", "thinking": "look"},
                     {"type": "text", "text": "running it"},
                     {"type": "tool_use", "id": "t1", "name": "Bash",
                      "input": {"command": "ls", "description": "list files"}},
                 ]}},
                {"type": "user", "timestamp": "2026-11-11T10:00:02Z",
                 "message": {"content": [
                     {"type": "tool_result", "tool_use_id": "t1",
                      "content": "file1\nfile2"},
                 ]}},
            ]
            stdout.write_text("\n".join(event(item) for item in first) + "\n",
                              encoding="utf-8")
            live = LiveLogs(output, "task-x", "synthesis")
            live.start()
            time.sleep(0.7)
            calls = (output / "tool-calls.jsonl").read_text(encoding="utf-8")
            chat = (output / "live.chat.md").read_text(encoding="utf-8")
            self.assertIn('"tool": "Bash"', calls)
            self.assertIn('"description": "list files"', calls)
            self.assertNotIn('"description"', json.loads(calls.splitlines()[0])["input"])
            self.assertIn("### Tool `Bash`", chat)
            self.assertIn("file1", chat)
            with stdout.open("a", encoding="utf-8") as handle:
                handle.write(event({"type": "result", "timestamp": "2026-11-11T10:00:03Z",
                                    "result": "done", "is_error": False}) + "\n")
            self.assertTrue(live.wait_for_result(5))
            live.stop()
            final_chat = (output / "live.chat.md").read_text(encoding="utf-8")
            self.assertIn("## Final result", final_chat)
            self.assertIn("done", final_chat)


class CompactResultTests(unittest.TestCase):
    def stream(self, output: Path, results: list[dict]) -> None:
        events = [
            {"type": "assistant", "timestamp": "2026-11-11T10:00:00Z",
             "message": {"id": "m1", "content": [{"type": "text", "text": "done"}]}},
            *results,
        ]
        (output / "stdout.jsonl").write_text(
            "\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")

    def test_real_result_wins_over_later_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.stream(output, [
                {"type": "result", "subtype": "success", "is_error": False,
                 "num_turns": 262, "duration_ms": 3567559,
                 "result": "real summary", "usage": {"input_tokens": 1},
                 "total_cost_usd": 1.5},
                {"type": "result", "subtype": "success", "is_error": False,
                 "num_turns": 0, "duration_ms": 17, "result": ""},
            ])
            result = _write_compact_logs(output)
            self.assertEqual(result.get("num_turns"), 262)
            self.assertEqual(result.get("result"), "real summary")
            sft = json.loads((output / "sft.jsonl").read_text().splitlines()[0])
            self.assertEqual(sft["metadata"]["result"]["num_turns"], 262)
            self.assertEqual(sft["metadata"]["result"]["result"], "real summary")
            chat = (output / "live.chat.md").read_text()
            self.assertEqual(chat.count("## Final result"), 1)

    def test_placeholder_first_does_not_hide_later_real_result(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.stream(output, [
                {"type": "result", "subtype": "success", "is_error": False,
                 "num_turns": 0, "duration_ms": 17, "result": ""},
                {"type": "result", "subtype": "success", "is_error": False,
                 "num_turns": 12, "duration_ms": 5000, "result": "real"},
            ])
            result = _write_compact_logs(output)
            self.assertEqual(result.get("num_turns"), 12)
            self.assertEqual(result.get("result"), "real")

    def test_placeholder_only_still_leaves_a_result_record(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.stream(output, [
                {"type": "result", "subtype": "success", "is_error": False,
                 "num_turns": 0, "duration_ms": 17, "result": ""},
            ])
            result = _write_compact_logs(output)
            self.assertEqual(result.get("num_turns"), 0)
            self.assertEqual((output / "live.chat.md").read_text().count("## Final result"), 1)


if __name__ == "__main__":
    unittest.main()