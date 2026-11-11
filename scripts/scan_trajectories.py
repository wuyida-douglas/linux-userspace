#!/usr/bin/env python3
"""Scan pipeline agent trajectories and emit per-task evidence digests (v2).

Reads only; writes digests under _audit/digests. Run with python3 -I.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path("/nvme/wuyida/新管线开发/results")
OUT = Path("/nvme/wuyida/新管线开发/_audit/digests")

SPECIAL_TOOLS = {
    "Task", "Agent", "Workflow", "Skill", "WebSearch", "WebFetch", "Monitor",
    "NotebookEdit", "CronCreate", "CronDelete", "CronList", "SendMessage",
    "ScheduleWakeup", "EnterWorktree", "ExitWorktree", "ListAgents",
    "TaskStop", "ToolSearch", "ReportFindings", "DesignSync",
}

NET_CMD_RE = re.compile(
    r"(?:^|[;&|(\s])(?:"
    r"docker\s+(?:pull|build|run|compose|push|commit|save|load|image)|"
    r"git\s+(?:clone|fetch|pull|ls-remote|submodule)|"
    r"apt(?:-get)?\s+(?:install|update)|pip3?\s+install|python3?\s+-m\s+pip|"
    r"npm\s+(?:install|i|ci|view|pack)|yarn|pnpm|"
    r"curl|wget|mvn|gradle|go\s+(?:get|mod)|cargo\s+(?:fetch|build)|"
    r"cmake|make|gcc|clang|tar\s+)"
)

MEM_RE = re.compile(r"/memory/|MEMORY\.md|\.claude/projects")
PRIOR_RE = re.compile(
    r"salvag|prior deliver|previous deliver|previous run|prior run|aborted iterate|"
    r"earlier (?:run|attempt)|re-?synth|reuse|old (?:deliver|run|attempt)", re.I)

# (name, regex, category): env = environment restriction; model = agent-side mistake
PATTERNS = [
    ("dns", re.compile(r"Could not resolve host|Temporary failure in name resolution|Name or service not known|Temporary failure resolving", re.I), "env"),
    ("conn_refused", re.compile(r"Connection refused|network is unreachable|No route to host", re.I), "env"),
    ("tls", re.compile(r"TLS handshake timeout|tls: failed to verify|certificate verify failed|SSL_ERROR", re.I), "env"),
    ("io_timeout", re.compile(r"i/o timeout|context deadline exceeded|context canceled|operation timed out", re.I), "env"),
    ("registry_403", re.compile(r"403 Forbidden|pull access denied|unauthorized:|authentication required|denied: requested access", re.I), "env"),
    ("registry_429", re.compile(r"429 Too Many Requests|toomanyrequests|Too Many Requests", re.I), "env"),
    ("registry_missing", re.compile(r"manifest unknown|manifest for .* not found|no matching manifest|not found: manifest", re.I), "model"),
    ("docker_daemon", re.compile(r"Cannot connect to the Docker daemon|permission denied while trying to connect to the Docker daemon|error during connect|docker: command not found", re.I), "env"),
    ("no_space", re.compile(r"No space left on device|no space left", re.I), "env"),
    ("oom", re.compile(r"Cannot allocate memory|out of memory|^Killed$|signal: killed", re.I), "env"),
    ("readonly", re.compile(r"Read-only file system|read-only file system", re.I), "env"),
    ("net_other", re.compile(r"Failed to connect|failed to fetch|Could not connect|network error|connection reset by peer|connection timed out|proxyconnect|Connection reset", re.I), "env"),
    ("api", re.compile(r"API Error|overloaded_error|rate_limit_error|rate limit|529|502 Bad Gateway|503 Service", re.I), "env"),
    ("tool_timeout", re.compile(r"timed out after|Command timed out|execution timed out", re.I), "env"),
    ("perm", re.compile(r"Permission denied|Operation not permitted", re.I), "env"),
    ("missing_cmd", re.compile(r"command not found", re.I), "model"),
    ("missing_file", re.compile(r"No such file or directory|File does not exist", re.I), "model"),
    ("build_fail", re.compile(r"failed to solve|Error response from daemon|docker build.*failed|make: \*\*\*|CMake Error|error: ", re.I), "model"),
    ("syntax", re.compile(r"SyntaxError|syntax error|unexpected token|invalid JSON|JSONDecodeError", re.I), "model"),
]


def text_of_block(b):
    c = b.get("content")
    if isinstance(c, str):
        return c
    out = []
    if isinstance(c, list):
        for x in c:
            if isinstance(x, dict):
                out.append(str(x.get("text", "")))
            else:
                out.append(str(x))
    return "\n".join(out)


def parse_time(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def norm_cmd(c):
    return re.sub(r"\s+", " ", c.strip())


def classify_ref(cmd, own_cwd):
    """Return list of (kind, ref) for cross-run references in a Bash command."""
    out = []
    # explicit results/<run>/batch-<b>/<task>
    for m in re.finditer(r"results/(iterate-[A-Za-z0-9._-]+)/(batch-[A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)", cmd):
        ref = f"results/{m.group(1)}/{m.group(2)}/{m.group(3)}"
        if ref not in own_cwd:
            kind = "same_task_prior" if m.group(3) in own_cwd else "other_task_prior"
            out.append((kind, ref))
    # glob over results/*
    if re.search(r"results/(?:iterate-\*|\*|iterate-[A-Za-z0-9._-]+/batch-\*|iterate-[A-Za-z0-9._-]+/batch-[A-Za-z0-9._-]+/\*)", cmd):
        out.append(("results_glob", cmd[:300]))
    return out


def scan_stage(task_dir: Path, stage: str, task_slug: str):
    d = task_dir / stage
    if not d.is_dir():
        return None
    res = {"stage": stage, "files": {}}
    for name in ("live.chat.md", "stdout.jsonl", "tool-calls.jsonl", "trajectory.jsonl", "result.json", "prompt.md", "sft.jsonl"):
        p = d / name
        if p.exists():
            res["files"][name] = {"path": str(p), "bytes": p.stat().st_size}
    init = {}
    stdout_path = d / "stdout.jsonl"
    if stdout_path.exists():
        with stdout_path.open() as f:
            try:
                init = json.loads(f.readline())
            except Exception:
                init = {}
    res["init"] = {
        "model": init.get("model"), "tools": init.get("tools"),
        "mcp_servers": init.get("mcp_servers"), "memory_paths": init.get("memory_paths"),
        "claude_code_version": init.get("claude_code_version"),
        "permissionMode": init.get("permissionMode"), "agents": init.get("agents"),
        "skills": init.get("skills"), "plugins": init.get("plugins"), "cwd": init.get("cwd"),
    }
    own_cwd = str(init.get("cwd") or "")
    # tool calls
    calls, by_id = [], {}
    tcs = d / "tool-calls.jsonl"
    if tcs.exists():
        with tcs.open() as f:
            for lineno, line in enumerate(f, 1):
                try:
                    c = json.loads(line)
                except Exception:
                    continue
                c["_line"] = lineno
                calls.append(c)
                if c.get("id"):
                    by_id[c["id"]] = c
    res["num_tool_calls"] = len(calls)
    res["tool_hist"] = dict(Counter(c.get("tool", "?") for c in calls))
    res["special_calls"] = [
        {"tool": c.get("tool"), "input": c.get("input"), "turn": c.get("turn"),
         "time": c.get("time"), "line": c["_line"]}
        for c in calls if c.get("tool") in SPECIAL_TOOLS
    ]
    cat = defaultdict(list)
    mem, prior, web, reads = [], [], [], []
    docker_cmds, selfcheck_cmds = [], []
    for c in calls:
        inp = c.get("input") or {}
        tool = c.get("tool")
        cmd = inp.get("command") if isinstance(inp, dict) else None
        fp = str(inp.get("file_path", "")) if isinstance(inp, dict) else ""
        if tool == "Read" and fp:
            reads.append({"path": fp, "turn": c.get("turn"), "line": c["_line"]})
            if MEM_RE.search(fp):
                mem.append({"kind": "read_memory", "path": fp, "turn": c.get("turn"),
                            "time": c.get("time"), "line": c["_line"]})
        if tool in ("Edit", "Write") and MEM_RE.search(fp):
            mem.append({"kind": "write_memory", "path": fp, "turn": c.get("turn"),
                        "time": c.get("time"), "line": c["_line"]})
        if isinstance(cmd, str):
            if NET_CMD_RE.search(cmd):
                cat["network"].append({"turn": c.get("turn"), "time": c.get("time"),
                                       "line": c["_line"], "command": cmd[:1500]})
            if MEM_RE.search(cmd):
                if re.search(r"\bsed\s+-i|\bcp\b|\bmv\b|\btee\b|>\s*\S*MEMORY|cat\s*>", cmd):
                    kind = "bash_write_memory"
                else:
                    kind = "bash_memory_path"
                mem.append({"kind": kind, "command": cmd[:1000], "turn": c.get("turn"),
                            "time": c.get("time"), "line": c["_line"]})
            if PRIOR_RE.search(cmd):
                prior.append({"reason": "prior_word", "command": cmd[:1200],
                              "turn": c.get("turn"), "time": c.get("time"), "line": c["_line"]})
            for kind, ref in classify_ref(cmd, own_cwd):
                prior.append({"reason": kind, "ref": ref, "command": cmd[:1200],
                              "turn": c.get("turn"), "time": c.get("time"), "line": c["_line"]})
            if re.search(r"\bdocker\s+(?:build|run|compose|commit|exec|save|load|image|pull)\b", cmd):
                docker_cmds.append({"turn": c.get("turn"), "line": c["_line"], "command": cmd[:400]})
            if re.search(r"pass2fail|selfcheck|self-check|run-selfcheck|oracle\.sh|healthcheck\.sh|solution\.sh", cmd):
                selfcheck_cmds.append({"turn": c.get("turn"), "line": c["_line"], "command": cmd[:400]})
        if tool in ("WebSearch", "WebFetch") and isinstance(inp, dict):
            web.append({"tool": tool, "input": inp, "turn": c.get("turn"),
                        "time": c.get("time"), "line": c["_line"]})
    res["network_calls"] = cat.get("network", [])
    res["memory_refs"] = mem
    res["prior_refs"] = prior
    res["web_calls"] = web
    res["reads"] = reads[:500]
    res["docker_cmd_count"] = len(docker_cmds)
    res["selfcheck_cmd_count"] = len(selfcheck_cmds)
    res["selfcheck_cmds"] = selfcheck_cmds[:40]
    reps = Counter(norm_cmd(c["input"]["command"]) for c in calls
                   if isinstance(c.get("input"), dict) and isinstance(c["input"].get("command"), str)
                   and len(norm_cmd(c["input"]["command"])) > 12)
    res["repeat_top"] = [{"command": k[:700], "count": v}
                         for k, v in reps.most_common(15) if v >= 3]
    # stdout: errors, api retry, permission denied, interrupts
    errs, sigs = [], Counter()
    result_rec, api_retry, perm_denied, interruptions = {}, [], [], []
    tool_result_total = err_total = env_err = model_err = 0
    last_time = None
    max_gap = (0, None)
    if stdout_path.exists():
        with stdout_path.open() as f:
            for lineno, line in enumerate(f, 1):
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                t = e.get("type")
                ts = parse_time(e.get("timestamp", ""))
                if ts:
                    if last_time and ts - last_time > 300:
                        max_gap = (max(1, int(ts - last_time)), e.get("timestamp"))
                    last_time = ts
                if t == "system" and e.get("subtype") in ("api_retry", "permission_denied"):
                    rec = {"subtype": e.get("subtype"), "line": lineno,
                           "time": e.get("timestamp"), "raw": json.dumps(e, ensure_ascii=False)[:900]}
                    (api_retry if e.get("subtype") == "api_retry" else perm_denied).append(rec)
                if t == "result":
                    result_rec = {"subtype": e.get("subtype"), "is_error": e.get("is_error"),
                                  "num_turns": e.get("num_turns"), "duration_ms": e.get("duration_ms"),
                                  "usage": e.get("usage"), "line": lineno}
                if t == "user":
                    msg = e.get("message") or {}
                    for b in msg.get("content") or []:
                        if not (isinstance(b, dict) and b.get("type") == "tool_result"):
                            continue
                        tool_result_total += 1
                        tur = e.get("tool_use_result")
                        if not isinstance(tur, dict):
                            tur = {}
                        if tur.get("interrupted"):
                            interruptions.append({"line": lineno, "timestamp": e.get("timestamp")})
                        tid = b.get("tool_use_id")
                        src = by_id.get(tid, {})
                        tool = src.get("tool", "?")
                        cmd = ""
                        if isinstance(src.get("input"), dict):
                            cmd = str(src["input"].get("command", ""))[:500]
                        txt = text_of_block(b)
                        stderr = str(tur.get("stderr") or "")
                        stdout = str(tur.get("stdout") or "")
                        iserr = bool(b.get("is_error"))
                        hay = stderr + "\n" + (stdout if iserr else "") + "\n" + (txt if iserr else "")
                        hits = [(n, c) for n, rx, c in PATTERNS if rx.search(hay)]
                        if not hits and iserr:
                            hits = [("other_error", "model")]
                        if not hits:
                            continue
                        err_total += 1
                        cats = {c for _, c in hits}
                        if "env" in cats:
                            env_err += 1
                        if "model" in cats:
                            model_err += 1
                        sig = re.sub(r"\s+", " ", (stderr or txt)[:240])
                        sigs[sig] += 1
                        errs.append({
                            "line": lineno, "timestamp": e.get("timestamp"), "tool": tool,
                            "is_error": iserr, "patterns": [n for n, _ in hits],
                            "categories": sorted(cats), "command": cmd,
                            "snippet": (stderr or txt)[:900],
                        })
    res["result_record"] = result_rec
    res["api_retry"] = api_retry
    res["permission_denied"] = perm_denied
    res["interruptions"] = interruptions
    res["tool_results"] = tool_result_total
    res["error_results"] = err_total
    res["env_error_results"] = env_err
    res["model_error_results"] = model_err
    res["errors"] = errs[:400]
    res["error_sigs"] = [{"snippet": k[:300], "count": v} for k, v in sigs.most_common(15)]
    res["max_gap_sec"] = max_gap[0]
    res["max_gap_at"] = max_gap[1]
    rj = d / "result.json"
    if rj.exists():
        try:
            res["stage_result"] = json.loads(rj.read_text())
        except Exception:
            pass
    return res


def scan_task(task_dir: Path):
    rec = {"task_dir": str(task_dir), "rel": str(task_dir.relative_to(ROOT))}
    rj = task_dir / "result.json"
    if rj.exists():
        try:
            rec["final"] = json.loads(rj.read_text())
        except Exception as e:
            rec["final_error"] = str(e)
    rec["stages"] = {}
    for st in ("route", "synthesis", "review"):
        s = scan_stage(task_dir, st, task_dir.name)
        if s:
            rec["stages"][st] = s
    return rec


def md_digest(rec):
    rel = rec["rel"]
    fin = rec.get("final") or {}
    L = [f"# Task digest: {rel}", ""]
    L.append(f"- final status: `{fin.get('status')}`  instance: `{fin.get('instance_id')}`")
    L.append(f"- task_id: `{fin.get('task_id')}`")
    for st in ("route", "synthesis", "review"):
        s = rec["stages"].get(st)
        if not s:
            L.append(f"- **{st}**: ABSENT")
            continue
        init = s.get("init", {})
        rr = s.get("result_record", {}) or {}
        L.append(f"- **{st}**: model=`{init.get('model')}` tools_available={len(init.get('tools') or [])} "
                 f"mcp={init.get('mcp_servers')} turns={rr.get('num_turns')} "
                 f"dur_ms={rr.get('duration_ms')} result={rr.get('subtype')} "
                 f"tool_calls={s.get('num_tool_calls')} tool_results={s.get('tool_results')} "
                 f"errors={s.get('error_results')}(env={s.get('env_error_results')},model={s.get('model_error_results')}) "
                 f"max_gap={s.get('max_gap_sec')}s")
        L.append(f"  - memory_paths: `{init.get('memory_paths')}`")
        L.append(f"  - tool_hist: `{json.dumps(s.get('tool_hist'), ensure_ascii=False)}`")
        L.append(f"  - special: {len(s.get('special_calls') or [])} {json.dumps([c['tool'] for c in (s.get('special_calls') or [])], ensure_ascii=False)}")
        L.append(f"  - web: {len(s.get('web_calls') or [])}  memory_refs: {len(s.get('memory_refs') or [])}  prior/cross-run: {len(s.get('prior_refs') or [])}  network_cmds: {len(s.get('network_calls') or [])}  docker_cmds: {s.get('docker_cmd_count')}  selfcheck_cmds: {s.get('selfcheck_cmd_count')}")
        L.append(f"  - api_retry: {len(s.get('api_retry') or [])}  permission_denied: {len(s.get('permission_denied') or [])}  interruptions: {len(s.get('interruptions') or [])}")
        if s.get("repeat_top"):
            L.append("  - repeated commands (>=3):")
            for r in s["repeat_top"][:8]:
                L.append(f"    - x{r['count']}: `{r['command'][:240]}`")
        def ev(title, items, fmt, limit=12):
            if not items:
                return
            L.append(f"  - **{title}** ({len(items)}):")
            for it in items[:limit]:
                L.append("    - " + fmt(it))
            if len(items) > limit:
                L.append(f"    - ... {len(items)-limit} more")
        ev("memory refs", s.get("memory_refs"), lambda i: f"[{i.get('kind')}] L{i.get('line')} t{i.get('turn')} {i.get('time')} :: `{(i.get('path') or i.get('command',''))[:300]}`", 15)
        ev("prior/cross-run refs", s.get("prior_refs"), lambda i: f"[{i.get('reason')}] L{i.get('line')} t{i.get('turn')} :: `{(i.get('command') or i.get('ref',''))[:500]}`", 25)
        ev("web calls", s.get("web_calls"), lambda i: f"{i['tool']} L{i['line']} t{i['turn']} :: `{json.dumps(i.get('input'),ensure_ascii=False)[:300]}`")
        ev("api_retry", s.get("api_retry"), lambda i: f"L{i['line']} {i.get('time')} `{i.get('raw','')[:300]}`")
        ev("permission_denied", s.get("permission_denied"), lambda i: f"L{i['line']} {i.get('time')} `{i.get('raw','')[:300]}`")
        ev("interruptions", s.get("interruptions"), lambda i: f"L{i['line']} {i.get('timestamp')}")
        ev("errors", s.get("errors"), lambda i: f"L{i.get('line')} {i.get('timestamp')} tool={i.get('tool')} err={i.get('is_error')} pat={i.get('patterns')} cmd=`{(i.get('command') or '')[:160]}` :: `{i.get('snippet','')[:300]}`", 35)
        if s.get("error_sigs"):
            L.append("  - **repeated error signatures**:")
            for e in s["error_sigs"][:10]:
                L.append(f"    - x{e['count']}: `{e['snippet'][:260]}`")
        ev("network cmds", s.get("network_calls"), lambda i: f"L{i.get('line')} t{i.get('turn')} :: `{i.get('command','')[:300]}`", 20)
        ev("selfcheck cmds", s.get("selfcheck_cmds"), lambda i: f"L{i.get('line')} t{i.get('turn')} :: `{i.get('command','')[:260]}`", 15)
    L.append("")
    L.append("## Stages full result summaries")
    for st in ("route", "synthesis", "review"):
        s = rec["stages"].get(st)
        if s and s.get("stage_result"):
            L.append(f"### {st}/result.json")
            L.append("```json")
            L.append(json.dumps(s["stage_result"], ensure_ascii=False, indent=1)[:6000])
            L.append("```")
    return "\n".join(L) + "\n"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    tasks = []
    for pat in ("iterate-20261109-08/batch-*/*", "iterate-20261110-01/batch-*/*"):
        for p in sorted(ROOT.glob(pat)):
            if p.is_dir():
                tasks.append(p)
    index = []
    for t in tasks:
        rec = scan_task(t)
        key = t.relative_to(ROOT).as_posix().replace("/", "__")
        (OUT / f"{key}.json").write_text(json.dumps(rec, ensure_ascii=False, indent=1))
        (OUT / f"{key}.md").write_text(md_digest(rec))
        index.append({"rel": rec["rel"], "key": key,
                      "status": (rec.get("final") or {}).get("status"),
                      "stages": list(rec["stages"].keys())})
        print(key)
    (OUT / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()