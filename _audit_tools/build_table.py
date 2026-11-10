#!/usr/bin/env python3
"""Build the deterministic per-task evidence table for the synthesis audit."""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("/nvme/wuyida/新管线开发/results")
OUT = Path("/nvme/wuyida/新管线开发/_audit")
MEMDIR = "/home/wuyida/.claude/projects/-nvme-wuyida------/memory/"


def ids(s):
    return set(x.lower() for x in re.findall(r"((?:cve|osv|ghsa)-[0-9]{4}-[0-9]+)", s, re.I))


rows = []
for tf in sorted(ROOT.glob("iterate-*/batch-*/*/synthesis/tool-calls.jsonl")):
    parts = tf.relative_to(ROOT).parts
    run, batch, task = parts[0] + "/" + parts[1], parts[1], parts[2]
    full_task = "/".join(parts[:3])
    cve = ids(task)
    task_dir = ROOT / full_task
    final = {}
    if (task_dir / "result.json").exists():
        try:
            final = json.loads((task_dir / "result.json").read_text())
        except Exception:
            pass
    calls = [json.loads(l) for l in tf.open()]
    tool_hist = Counter(c.get("tool") for c in calls)
    # prior delivery full copy
    prior_full = []
    for ln, c in enumerate(calls, 1):
        cmd = (c.get("input") or {}).get("command", "") or ""
        if "cp " not in cmd or "results/" not in cmd:
            continue
        vars = dict(re.findall(r"(\w+)=(/nvme/wuyida/新管线开发/results/[^\s;&|\"']+)", cmd))
        for m in re.finditer(r"\bcp\s+-[a-zA-Z]+\s+([^\n;&|]+)", cmd):
            toks = m.group(1).split()
            src = toks[0].strip("\"'") if toks else ""
            dst = toks[1].strip("\"'") if len(toks) > 1 else ""
            for v, p in vars.items():
                src = src.replace("$" + v, p).replace("${" + v + "}", p)
                dst = dst.replace("$" + v, p).replace("${" + v + "}", p)
            sm = re.search(r"/nvme/wuyida/新管线开发/results/(iterate-[^/]+)/(batch-[^/]+)/([^/]+)", src)
            if not sm or "/delivery" not in src:
                continue
            if sm.group(1) == parts[0]:
                continue
            if ids(src) != cve:
                continue
            if re.search(r"(^|/)delivery/?$", dst) or dst.rstrip(")") in ("", ".", "./"):
                prior_full.append({"line": ln, "turn": c.get("turn"), "src_run": sm.group(1),
                                   "src": src.split("/results/")[-1]})
    # memory recipe read
    recipe_files, generic_files, mem_md = set(), set(), False
    for c in calls:
        tool = c.get("tool")
        inp = c.get("input") or {}
        cands = []
        if tool == "Read" and isinstance(inp.get("file_path"), str):
            cands.append(inp["file_path"])
        if isinstance(inp.get("command"), str):
            for m in re.finditer(r"/home/wuyida/\.claude/projects/[^/\s\"'`]+/memory/([^\s\"'`;|&]+)", inp["command"]):
                cands.append(MEMDIR + m.group(1))
        for p in cands:
            if "/memory/" not in p:
                continue
            fn = p.strip("\"'").split("/")[-1]
            if fn == "MEMORY.md":
                mem_md = True
            elif fn.endswith(".md"):
                if ids(fn) & cve:
                    recipe_files.add(fn)
                else:
                    generic_files.add(fn)
    # env/tooling patterns from stdout
    stdout = (task_dir / "synthesis" / "stdout.jsonl")
    txt = stdout.read_text(errors="ignore") if stdout.exists() else ""
    env = {
        "blocked_sleep": len(re.findall(r"Blocked: sleep", txt)),
        "timeout0": len(re.findall(r"Command timed out after 0s", txt)),
        "exit143": len(re.findall(r"Exit code 143", txt)),
        "tool_use_error": len(re.findall(r"<tool_use_error>", txt)),
        "daemon": len(re.findall(r"Cannot connect to the Docker daemon|permission denied while trying to connect", txt)),
        "no_space": len(re.findall(r"No space left on device", txt)),
        "api_retry": len(re.findall(r"API Error|overloaded_error|rate_limit_error", txt)),
    }
    # result record
    res = {}
    traj = task_dir / "synthesis" / "trajectory.jsonl"
    if traj.exists():
        for line in traj.open():
            d = json.loads(line)
            if d.get("type") == "result":
                res = d
    dg = OUT / "digests" / (full_task.replace("/", "__") + ".json")
    dgdata = json.loads(dg.read_text()) if dg.exists() else {}
    synth = (dgdata.get("stages") or {}).get("synthesis") or {}
    rows.append({
        "task": full_task, "run": run, "final_status": final.get("status"),
        "turns": res.get("num_turns"), "duration_ms": res.get("duration_ms"),
        "result_subtype": res.get("subtype"),
        "tool_calls": len(calls), "tool_hist": dict(tool_hist),
        "special_tools": sorted(t for t in tool_hist if t in {
            "ToolSearch", "Monitor", "TaskStop", "Task", "Workflow", "Skill",
            "WebSearch", "WebFetch", "SendMessage", "CronCreate", "CronList", "CronDelete"}),
        "web_calls": len(synth.get("web_calls") or []),
        "prior_delivery_full": prior_full,
        "prior_delivery_full_count": len(prior_full),
        "memory_recipe_files": sorted(recipe_files),
        "memory_generic_files": sorted(generic_files),
        "memory_md": mem_md,
        "env": env,
        "error_results": synth.get("error_results"),
        "env_error_results": synth.get("env_error_results"),
        "max_gap_sec": synth.get("max_gap_sec"),
        "review_passed": (final.get("review") or {}).get("passed"),
        "harbor_status": (final.get("harbor") or {}).get("status"),
        "gold_reward": ((final.get("harbor") or {}).get("gold") or {}).get("reward"),
        "null_reward": ((final.get("harbor") or {}).get("null") or {}).get("reward"),
    })

(OUT / "task_table.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1))

# markdown
L = ["# 合成轨迹逐题证据表", "",
     "| task | status | turns | 复制旧交付 | 读任务配方 | blocked_sleep | timeout0 | exit143 | special tools | web | gold/null |",
     "|---|---|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    L.append("| {task} | {status} | {turns} | {copy} | {recipe} | {bs} | {t0} | {e143} | {sp} | {web} | {g}/{n} |".format(
        task=r["task"].replace("iterate-", ""), status=r["final_status"], turns=r["turns"],
        copy=("YES:" + ",".join(x["src_run"] for x in r["prior_delivery_full"])) if r["prior_delivery_full"] else "-",
        recipe=("YES:" + ",".join(x.split("-")[0] for x in r["memory_recipe_files"])) if r["memory_recipe_files"] else ("MEMORY.md" if r["memory_md"] else "-"),
        bs=r["env"]["blocked_sleep"] or "-", t0=r["env"]["timeout0"] or "-", e143=r["env"]["exit143"] or "-",
        sp=",".join(r["special_tools"]) or "-", web=r["web_calls"] or "-",
        g=r["gold_reward"], n=r["null_reward"]))
(OUT / "task_table.md").write_text("\n".join(L) + "\n")

# summary
print("tasks", len(rows))
print("prior full copy", sum(1 for r in rows if r["prior_delivery_full"]))
print("recipe read (exact id)", sum(1 for r in rows if r["memory_recipe_files"]))
print("MEMORY.md read", sum(1 for r in rows if r["memory_md"]))
print("blocked_sleep tasks", sum(1 for r in rows if r["env"]["blocked_sleep"]))
print("timeout0 tasks", sum(1 for r in rows if r["env"]["timeout0"]))
print("exit143 tasks", sum(1 for r in rows if r["env"]["exit143"]))
print("max_turns", sum(1 for r in rows if r["result_subtype"] == "error_max_turns"))
print("special tool tasks", sum(1 for r in rows if r["special_tools"]))
print("web tasks", sum(1 for r in rows if r["web_calls"]))