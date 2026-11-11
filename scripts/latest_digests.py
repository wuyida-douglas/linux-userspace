#!/usr/bin/env python3
"""Digest the latest passed synthesis runs for the memory/prior-artifact audit."""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path("/nvme/wuyida/新管线开发/results")
OUT = Path("/nvme/wuyida/新管线开发/_audit/latest")
RUNS = ["iterate-20261110-06", "iterate-20261110-07", "iterate-20261110-08"]
MEM_RE = re.compile(r"/home/wuyida/\.claude/projects/[^\s\"'`;|&]*?/memory/[^\s\"'`;|&]+")
RES_RE = re.compile(r"/nvme/wuyida/新管线开发/results/(iterate-[^/\s\"'`;|&]+)/batch-([^/\s\"'`;|&]+)/([^/\s\"'`;|&)]+)")


def under(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root)
    except Exception:
        return False


def scan(task_dir: Path):
    syn = task_dir / "synthesis"
    try:
        init = json.loads((syn / "stdout.jsonl").read_text().splitlines()[0])
    except Exception:
        init = {}
    cwd = Path(init.get("cwd") or task_dir / "workspace").resolve()
    root = cwd.parent if cwd.name == "workspace" else cwd
    calls = []
    try:
        calls = [json.loads(l) for l in (syn / "tool-calls.jsonl").open()]
    except Exception:
        pass
    mem, iso, prior, cp_prior = [], [], [], []
    for lineno, call in enumerate(calls, 1):
        inp = call.get("input") or {}
        tool = call.get("tool")
        path = str(inp.get("file_path", "")) if isinstance(inp, dict) else ""
        cmd = str(inp.get("command", "")) if isinstance(inp, dict) else ""
        if path:
            if MEM_RE.search(path):
                mem.append({"line": lineno, "turn": call.get("turn"), "kind": "Read",
                            "path": path})
            elif re.search(r"\.agent-(config|home|guard)", path):
                iso.append({"line": lineno, "turn": call.get("turn"), "kind": "Read",
                            "path": path})
        if cmd:
            for m in MEM_RE.finditer(cmd):
                mem.append({"line": lineno, "turn": call.get("turn"), "kind": "Bash",
                            "path": m.group(0)})
            if re.search(r"\.agent-(config|home|guard)", cmd):
                iso.append({"line": lineno, "turn": call.get("turn"), "kind": "Bash",
                            "path": cmd[:240]})
            for m in RES_RE.finditer(cmd):
                ref = (Path("/nvme/wuyida/新管线开发/results") / m.group(1)
                       / ("batch-" + m.group(2)) / m.group(3))
                if under(ref, root):
                    continue
                item = {"line": lineno, "turn": call.get("turn"),
                        "ref": str(ref), "exists": ref.exists(),
                        "command": cmd[:420]}
                prior.append(item)
                if re.search(r"\bcp\s+-[a-zA-Z]*[aArR]", cmd):
                    cp_prior.append(item)
    # guard log
    blocks = []
    gl = syn / ".agent-guard.log"
    if gl.exists():
        for line in gl.read_text(errors="replace").splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("decision") != "block":
                continue
            detail = str(d.get("detail") or "")
            refs = []
            for m in RES_RE.finditer(detail):
                ref = (Path("/nvme/wuyida/新管线开发/results") / m.group(1)
                       / ("batch-" + m.group(2)) / m.group(3))
                if not under(ref, root):
                    refs.append({"ref": str(ref), "exists": ref.exists()})
            blocks.append({"reason": d.get("reason"), "detail": detail[:500],
                           "refs": refs, "memory": bool(MEM_RE.search(detail))})
    sft_mem = False
    sft = syn / "sft.jsonl"
    if sft.exists():
        sft_mem = bool(MEM_RE.search(sft.read_text(errors="replace")))
    return {"task_dir": str(task_dir), "root": str(root), "init": init, "mem": mem,
            "iso": iso, "prior": prior, "cp_prior": cp_prior, "blocks": blocks,
            "sft_mem": sft_mem}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "digests").mkdir(exist_ok=True)
    tasks = []
    for run in RUNS:
        for rj in sorted(ROOT.glob(f"{run}/batch-*/*/result.json")):
            td = rj.parent
            try:
                res = json.loads(rj.read_text())
            except Exception:
                continue
            if res.get("status") != "passed" or not (td / "synthesis").is_dir():
                continue
            tasks.append((run, td, res))
    rows, index = [], []
    for run, td, res in tasks:
        data = scan(td)
        data["run"] = run
        data["task"] = td.name
        data["status"] = res.get("status")
        data["turns"] = (res.get("synthesis_agent") or {}).get("num_turns")
        key = f"{run}__{td.name}"
        (OUT / "digests" / f"{key}.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=1))
        exists_prior = [x for x in data["prior"] if x["exists"]]
        real_blocks = [b for b in data["blocks"] if any(x["exists"] for x in b["refs"])]
        md = [
            f"# {run}/{td.name}", "",
            f"- final status: `{data['status']}`  turns: `{data['turns']}`",
            f"- init memory_paths: `{data['init'].get('memory_paths')}`",
            f"- actual memory refs: **{len(data['mem'])}**",
            f"- isolation (.agent-*) refs: {len(data['iso'])}",
            f"- prior refs: {len(data['prior'])}  existing: **{len(exists_prior)}**",
            f"- prior cp: {len(data['cp_prior'])}  existing: **{sum(1 for x in data['cp_prior'] if x['exists'])}**",
            f"- guard blocks: {len(data['blocks'])}  blocks with an existing outside path: **{len(real_blocks)}**",
            f"- sft actual memory content: **{data['sft_mem']}**",
            "",
        ]
        if data["mem"]:
            md.append("## Actual memory refs")
            for x in data["mem"]:
                md.append(f"- L{x['line']} t{x.get('turn')} {x['kind']} `{x.get('path')}`")
        if data["iso"]:
            md.append("## Isolation (.agent-*) refs (per-stage config, not shared memory)")
            for x in data["iso"]:
                md.append(f"- L{x['line']} t{x.get('turn')} {x['kind']} `{x.get('path')}`")
        if data["prior"]:
            md.append("## Prior results refs")
            for x in data["prior"]:
                md.append(f"- L{x['line']} t{x.get('turn')} exists={x['exists']} `{x['ref']}` :: `{x['command'][:260]}`")
        if data["blocks"]:
            md.append("## Guard blocks")
            for b in data["blocks"]:
                md.append(f"- reason={b['reason']} memory={b['memory']} refs={json.dumps(b['refs'], ensure_ascii=False)} :: `{b['detail'][:260]}`")
        (OUT / "digests" / f"{key}.md").write_text("\n".join(md) + "\n")
        rows.append({"run": run, "task": td.name, "key": key,
                     "mem": len(data["mem"]), "iso": len(data["iso"]),
                     "prior": len(data["prior"]), "prior_exists": len(exists_prior),
                     "cp": len(data["cp_prior"]),
                     "cp_exists": sum(1 for x in data["cp_prior"] if x["exists"]),
                     "blocks": len(data["blocks"]), "real_blocks": len(real_blocks),
                     "sft_mem": data["sft_mem"],
                     "init_memory": data["init"].get("memory_paths")})
        index.append({"run": run, "task": td.name, "key": key})
    (OUT / "index.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1))
    # 5 balanced groups, round-robin
    groups = {f"G{i+1}": [] for i in range(5)}
    for i, row in enumerate(rows):
        groups[f"G{i % 5 + 1}"].append(row["key"])
    (OUT / "groups.json").write_text(json.dumps(groups, ensure_ascii=False, indent=1))
    print("tasks", len(rows))
    print("init memory None", sum(1 for r in rows if r["init_memory"] is None))
    print("mem refs", sum(1 for r in rows if r["mem"]))
    print("prior refs existing", sum(r["prior_exists"] for r in rows))
    print("prior cp existing", sum(r["cp_exists"] for r in rows))
    print("sft memory", sum(1 for r in rows if r["sft_mem"]))
    print("blocks tasks", sum(1 for r in rows if r["blocks"]))
    print("real blocks tasks", sum(1 for r in rows if r["real_blocks"]))
    for g, keys in groups.items():
        print(g, len(keys))


if __name__ == "__main__":
    main()