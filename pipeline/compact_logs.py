#!/usr/bin/env python3
"""Build readable logs from an existing Claude Code stdout.jsonl.

The raw stream is preserved. This writes:
  trajectory.jsonl          small turn index for supervisors
  tool-calls.jsonl          one line per tool use, Beijing timestamp first
  live.chat.md              full thinking/text/tool/result/compaction transcript
  sft.jsonl                 message-structured trajectory for SFT
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import prompts
from .agent import LiveLogs, _write_compact_logs
from .common import write_json


def _reconstruct_prompt(path: Path) -> tuple[str, dict] | None:
    """Recover the initial prompt for legacy runs from the current constants.

    New runs write prompt.md directly. Historical runs did not, so for route,
    synthesis and review we can reconstruct the exact constant prompt (and the
    branch guide for synthesis). It is marked as reconstructed, never passed
    off as recorded evidence.
    """
    stage = path.name
    if stage == "route":
        return prompts.ROUTE, {"source": "reconstructed_current_prompts",
                               "stage": stage}
    if stage == "review":
        return prompts.REVIEW, {"source": "reconstructed_current_prompts",
                                "stage": stage}
    if stage == "synthesis":
        try:
            route = json.loads((path.parent / "workspace/route.json").read_text(
                encoding="utf-8"))
            branch = route.get("branch")
            if branch in prompts.BRANCH_GUIDES:
                return prompts.branch_prompt(branch), {
                    "source": "reconstructed_current_prompts",
                    "stage": stage, "branch": branch}
        except (OSError, json.JSONDecodeError):
            pass
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path,
                        help="synthesis directories containing stdout.jsonl")
    parser.add_argument("--follow", action="store_true",
                        help="keep tool-calls.jsonl and live.chat.md updated while an agent runs")
    args = parser.parse_args()
    if args.follow and len(args.paths) != 1:
        parser.error("--follow requires exactly one path")
    for path in args.paths:
        if not (path / "stdout.jsonl").is_file():
            print(f"skip {path}: no stdout.jsonl")
            continue
        if args.follow:
            live = LiveLogs(path, path.parent.name, path.name)
            live.start()
            print(f"following {path}/stdout.jsonl -> "
                  f"{path}/tool-calls.jsonl, {path}/live.chat.md")
            try:
                live.wait_for_result()
            except KeyboardInterrupt:
                pass
            finally:
                live.stop()
            continue
        if not (path / "prompt.md").is_file():
            reconstructed = _reconstruct_prompt(path)
            if reconstructed:
                text, source = reconstructed
                (path / "prompt.md").write_text(text, encoding="utf-8")
                write_json(path / "prompt.source.json", source)
        _write_compact_logs(path, "trajectory.jsonl")
        print(f"wrote {path}/trajectory.jsonl, live.chat.md, sft.jsonl, tool-calls.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
