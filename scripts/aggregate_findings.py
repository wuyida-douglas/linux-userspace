#!/usr/bin/env python3
"""Aggregate reviewer findings G1-G8 into totals and a per-task verdict table."""
import json
from collections import Counter, defaultdict
from pathlib import Path

F = Path("/nvme/wuyida/新管线开发/_audit/findings")
criteria = ["C1_environment", "C2_generic_tools", "C3_smoothness",
            "C4_genuine_interaction", "C5_no_hack"]
totals = {c: Counter() for c in criteria}
per_task = {}
groups = {}
for p in sorted(list(F.glob("G[1-7].json")) + list(F.glob("GX.json"))):
    d = json.loads(p.read_text())
    groups[p.stem] = {"tasks": len(d.get("tasks") or []),
                      "systemic": d.get("group_systemic_findings") or []}
    for t in d.get("tasks") or []:
        per_task[t["task"]] = {"group": p.stem, "final_status": t.get("final_status"),
                               "notes": t.get("notes", ""),
                               "criteria": {}}
        for c in criteria:
            v = (t.get("criteria") or {}).get(c) or {}
            per_task[t["task"]]["criteria"][c] = {
                "verdict": v.get("verdict"), "severity": v.get("severity"),
                "confidence": v.get("confidence"), "evidence": v.get("evidence") or []}
            totals[c][v.get("verdict") or "missing"] += 1

print("reviewed tasks:", len(per_task))
for c in criteria:
    print(c, dict(totals[c]))
print("\ngroups:", {k: v["tasks"] for k, v in groups.items()})
Path("/nvme/wuyida/新管线开发/_audit/findings/aggregate.json").write_text(
    json.dumps({"totals": {c: dict(t) for c, t in totals.items()},
                "per_task": per_task, "groups": groups}, ensure_ascii=False, indent=1))

# per-task markdown
L = ["# Reviewer 逐题判定汇总", "",
     "| task | status | C1 | C2 | C3 | C4 | C5 | notes |",
     "|---|---|---|---|---|---|---|---|"]
for task, v in sorted(per_task.items()):
    def s(c):
        x = v["criteria"].get(c) or {}
        return f"{x.get('verdict') or '?'}" + (f"/{x.get('severity')}" if x.get("severity") not in (None, "none") else "")
    L.append(f"| {task} | {v.get('final_status')} | {s('C1_environment')} | {s('C2_generic_tools')} | "
             f"{s('C3_smoothness')} | {s('C4_genuine_interaction')} | {s('C5_no_hack')} | {str(v.get('notes',''))[:120].replace('|','/')} |")
Path("/nvme/wuyida/新管线开发/_audit/findings/aggregate.md").write_text("\n".join(L) + "\n")