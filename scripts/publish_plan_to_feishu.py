#!/usr/bin/env python3
"""Append the current plan to the specified Feishu document as native blocks."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / ".cursor/skills/feishu-wiki-reader"))
from feishu_read import tool  # noqa: E402


def text_block(content: str, block_type: int = 2) -> dict:
    style = "heading1" if block_type == 3 else "heading2" if block_type == 4 else "heading3" if block_type == 5 else "text"
    return {
        "block_type": block_type,
        style: {"elements": [{"text_run": {"content": content}}]},
    }


def blocks(markdown: str) -> list[dict]:
    result = []
    paragraph: list[str] = []
    code = False
    code_lines: list[str] = []

    def flush() -> None:
        if paragraph:
            result.append(text_block("\n".join(paragraph)))
            paragraph.clear()

    for line in markdown.splitlines():
        if line.startswith("```"):
            flush()
            if code:
                result.append(text_block("\n".join(code_lines)))
                code_lines.clear()
            code = not code
            continue
        if code:
            code_lines.append(line)
            continue
        if not line.strip():
            flush()
        elif line.startswith("### "):
            flush()
            result.append(text_block(line[4:], 5))
        elif line.startswith("## "):
            flush()
            result.append(text_block(line[3:], 4))
        elif line.startswith("# "):
            flush()
            result.append(text_block(line[2:], 3))
        else:
            paragraph.append(line)
            if sum(map(len, paragraph)) > 1200:
                flush()
    flush()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("document_id")
    parser.add_argument("markdown", type=Path)
    args = parser.parse_args()
    content = args.markdown.read_text(encoding="utf-8")
    items = blocks(content)
    response = tool("docx_v1_documentBlockChildren_get", {
        "path": {"document_id": args.document_id, "block_id": args.document_id},
        "query": {"page_size": 500},
    })
    payload = json.loads(response["result"]["content"][0]["text"])
    if payload.get("code") != 0:
        raise RuntimeError(payload)
    index = len(payload["data"].get("items") or [])
    for offset in range(0, len(items), 40):
        batch = items[offset:offset + 40]
        response = tool("docx_v1_documentBlockChildren_create", {
            "path": {"document_id": args.document_id, "block_id": args.document_id},
            "query": {"document_revision_id": -1},
            "body": {"children": batch, "index": index + offset},
        })
        payload = json.loads(response["result"]["content"][0]["text"])
        if payload.get("code") != 0:
            raise RuntimeError(payload)
        print(f"appended {offset + len(batch)}/{len(items)} blocks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
