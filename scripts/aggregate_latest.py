#!/usr/bin/env python3
"""Aggregate the latest-run memory/prior-artifact reviewer findings."""
import json
from collections import Counter
from pathlib import Path

F = Path("/nvme/wuyida/新管线开发/_audit/latest/findings")
rows = []
for p in sorted(F.glob("G[1-5].json")):
    d = json.loads(p.read_text())
    for t in d.get("tasks") or []:
        rows.append({"group": p.stem, **t})
print("tasks", len(rows))
print(Counter(r.get("verdict") for r in rows))
for r in rows:
    if r.get("verdict") not in {"clean", None}:
        print(r.get("group"), r.get("task"), r.get("verdict"), r.get("notes", "")[:200])
out = {"counts": dict(Counter(r.get("verdict") for r in rows)), "tasks": rows}
(F / "aggregate.json").write_text(json.dumps(out, ensure_ascii=False, indent=1))
L = ["# 最新批次 memory/旧产物审计汇总", "", "| group | task | verdict | notes |", "|---|---|---|---|"]
for r in sorted(rows, key=lambda x: (x.get("group"), x.get("task", ""))):
    L.append(f"| {r.get('group')} | {r.get('task')} | {r.get('verdict')} | {str(r.get('notes',''))[:120].replace('|','/')} |")
(F / "aggregate.md").write_text("\n".join(L) + "\n")