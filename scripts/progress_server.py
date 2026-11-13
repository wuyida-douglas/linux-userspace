#!/usr/bin/env python3
"""Read-only progress dashboard for a running synthesis batch.

Serves a single self-contained page plus a JSON endpoint:

    python3 scripts/progress_server.py --port 8770

The page shows the cumulative terminal/passed curve, the throughput per
15-minute bucket (to expose slowdowns), and the terminal-result composition.
Nothing is written; the batch keeps running untouched.
"""
from __future__ import annotations

import argparse
import json
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TERMINAL = ("passed", "rejected", "failed", "error", "timeout")
IN_PROGRESS = ("routing", "synthesizing", "reviewing", "harbor", "preparing")
IMAGE_LOOP_MARKERS = ("failed to rebuild", "is missing", "shared image archive differs")
BUCKET_SEC = 15 * 60


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def category(record: dict) -> str:
    status = str(record.get("status") or "")
    failure = str(record.get("failure_class") or "")
    if status == "passed":
        return "passed"
    if status == "rejected":
        return "not_suitable" if failure == "not_suitable" else "rejected_other"
    if status == "timeout":
        return "timeout"
    if status == "error":
        error = str(record.get("error") or "")
        return "image_cleanup" if any(m in error for m in IMAGE_LOOP_MARKERS) else "infra_error"
    if status == "failed":
        if failure == "review_rejected":
            return "review_rejected"
        if failure.startswith("synthesis"):
            return "synthesis"
        if failure == "harbor_failed":
            return "harbor_failed"
        return "failed_other"
    return "other"


def collect(results: Path, fresh_file: Path | None, since: float = 0.0) -> dict:
    cohort = set()
    if fresh_file and fresh_file.is_file():
        cohort = {line.strip() for line in fresh_file.read_text().splitlines() if line.strip()}
    now = time.time()
    events = []          # (mtime, category)
    in_progress = {}
    counts = {}
    for path in results.glob("*/result.json"):
        task = path.parent.name
        if cohort and task not in cohort:
            continue
        record = load(path)
        status = str(record.get("status") or "")
        if status in IN_PROGRESS:
            in_progress[status] = in_progress.get(status, 0) + 1
            continue
        if status not in TERMINAL:
            continue
        mtime = path.stat().st_mtime
        if since and mtime < since:
            continue
        kind = category(record)
        counts[kind] = counts.get(kind, 0) + 1
        events.append((mtime, kind))
    events.sort()

    denominator = sum(v for k, v in counts.items()
                      if k not in ("not_suitable", "image_cleanup", "other"))
    passed = counts.get("passed", 0)
    rate_b = round(passed / denominator * 100, 1) if denominator else 0.0

    # cumulative curves, sampled at every terminal event
    series_t, series_term, series_pass = [], [], []
    term = run = 0
    for mtime, kind in events:
        term += 1
        run += 1 if kind == "passed" else 0
        series_t.append(int(mtime))
        series_term.append(term)
        series_pass.append(run)

    # throughput per 15-minute bucket over the last 6 hours
    buckets = []
    start = int(now // BUCKET_SEC * BUCKET_SEC) - 23 * BUCKET_SEC
    for i in range(24):
        buckets.append({"t0": start + i * BUCKET_SEC, "terminals": 0, "passed": 0})
    for mtime, kind in events:
        idx = int((mtime - start) // BUCKET_SEC)
        if 0 <= idx < 24:
            buckets[idx]["terminals"] += 1
            if kind == "passed":
                buckets[idx]["passed"] += 1

    def window(seconds: int) -> dict:
        cut = now - seconds
        sel = [k for m, k in events if m >= cut]
        return {"terminals": len(sel), "passed": sel.count("passed")}

    disk = {}
    for label, path in (("nvme", "/nvme"), ("root", "/")):
        try:
            disk[f"{label}_free_gb"] = round(shutil.disk_usage(path).free / 1024 ** 3)
        except OSError:
            pass

    order = ["passed", "review_rejected", "synthesis", "harbor_failed",
             "infra_error", "image_cleanup", "not_suitable", "failed_other",
             "rejected_other", "timeout", "other"]
    labels = {
        "passed": "passed", "review_rejected": "review 拒绝", "synthesis": "合成失败",
        "harbor_failed": "验收失败", "infra_error": "基础设施错误",
        "image_cleanup": "镜像清理副作用", "not_suitable": "路由拒绝（不计分母）",
        "failed_other": "其他 failed", "rejected_other": "其他 rejected",
        "timeout": "超时", "other": "其他",
    }
    categories = [{"key": k, "label": labels[k], "count": counts[k]}
                  for k in order if counts.get(k)]
    return {
        "generated_at": int(now),
        "cohort": len(cohort),
        "terminal": len(events),
        "passed": passed,
        "rate_b": {"pct": rate_b, "denominator": denominator},
        "in_progress": in_progress,
        "in_progress_total": sum(in_progress.values()),
        "categories": categories,
        "series": {"t": series_t, "terminals": series_term, "passed": series_pass},
        "buckets": buckets,
        "speed": {"last_hour": window(3600), "prev_hour": window(7200) | {
            "terminals": window(7200)["terminals"] - window(3600)["terminals"],
            "passed": window(7200)["passed"] - window(3600)["passed"]}},
        "disk": disk,
    }


_cache: dict = {"at": 0.0, "payload": None}
_cache_lock = threading.Lock()


def stats(results: Path, fresh: Path | None, since: float = 0.0) -> dict:
    with _cache_lock:
        if _cache["payload"] is not None and time.time() - _cache["at"] < 10:
            return _cache["payload"]
        payload = collect(results, fresh, since)
        _cache.update(at=time.time(), payload=payload)
        return payload


PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>合成进度</title>
<style>
  :root {
    color-scheme: light;
    --surface-0: #f4f3f0;
    --surface-1: #fcfcfb;
    --border: #e2e0da;
    --text-primary: #0b0b0b;
    --text-secondary: #52514e;
    --text-muted: #86847d;
    --grid: #e8e6e0;
    --series-1: #2a78d6;
    --series-2: #eb6834;
    --series-3: #1baf7a;
    --series-4: #eda100;
    --series-5: #e87ba4;
    --series-6: #008300;
    --series-7: #6250d6;
    --series-8: #e34948;
  }
  @media (prefers-color-scheme: dark) {
    :root:where(:not([data-theme="light"])) {
      color-scheme: dark;
      --surface-0: #121211;
      --surface-1: #1a1a19;
      --border: #2c2c2a;
      --text-primary: #f0efec;
      --text-secondary: #c3c2b7;
      --text-muted: #8d8c85;
      --grid: #262624;
      --series-1: #3987e5;
      --series-2: #d95926;
      --series-3: #199e70;
      --series-4: #c98500;
      --series-5: #d55181;
      --series-6: #008300;
      --series-7: #9085e9;
      --series-8: #e66767;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px 20px 48px;
    background: var(--surface-0); color: var(--text-primary);
    font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
          "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  }
  .wrap { max-width: 1180px; margin: 0 auto; }
  header { display: flex; align-items: baseline; justify-content: space-between;
           gap: 16px; flex-wrap: wrap; margin-bottom: 18px; }
  h1 { font-size: 18px; font-weight: 600; margin: 0; letter-spacing: .2px; }
  .meta { color: var(--text-muted); font-size: 12px; }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 12px; margin-bottom: 16px; }
  .tile { background: var(--surface-1); border: 1px solid var(--border);
          border-radius: 10px; padding: 14px 16px; }
  .tile .label { color: var(--text-secondary); font-size: 12px; }
  .tile .value { font-size: 26px; font-weight: 600; margin-top: 4px;
                 font-variant-numeric: tabular-nums; }
  .tile .sub { color: var(--text-muted); font-size: 12px; margin-top: 2px; }
  .card { background: var(--surface-1); border: 1px solid var(--border);
          border-radius: 10px; padding: 16px 18px 12px; margin-bottom: 16px; }
  .card h2 { font-size: 13px; font-weight: 600; margin: 0 0 2px; }
  .card .hint { color: var(--text-muted); font-size: 12px; margin: 0 0 10px; }
  .chart { position: relative; }
  svg { display: block; width: 100%; height: auto; overflow: visible; }
  .legend { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px;
            color: var(--text-secondary); margin-top: 8px; }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .swatch { width: 10px; height: 10px; border-radius: 3px; display: inline-block; }
  .tooltip { position: absolute; pointer-events: none; background: var(--surface-1);
             border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px;
             font-size: 12px; color: var(--text-primary); box-shadow: 0 4px 14px rgba(0,0,0,.12);
             opacity: 0; transition: opacity .12s; white-space: nowrap; z-index: 5; }
  .tooltip b { font-variant-numeric: tabular-nums; }
  .grid2 { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr); gap: 16px; }
  @media (max-width: 820px) { .grid2 { grid-template-columns: 1fr; } }
  details { margin-top: 6px; color: var(--text-secondary); font-size: 12px; }
  table { border-collapse: collapse; margin-top: 8px; font-variant-numeric: tabular-nums; }
  td, th { text-align: left; padding: 3px 14px 3px 0; font-weight: 400; }
  th { color: var(--text-muted); }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block;
         margin-right: 6px; vertical-align: -1px; }
  .empty { color: var(--text-muted); font-size: 12px; padding: 40px 0; text-align: center; }
  #donutChart { max-width: 230px; margin: 0 auto; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>合成进度</h1>
      <div class="meta" id="meta">加载中…</div>
    </div>
    <div class="meta" id="stamp"></div>
  </header>

  <div class="kpis" id="kpis"></div>

  <div class="card">
    <h2>累计产出</h2>
    <p class="hint">从本次运行开始累计：终态题数与其中 passed 数</p>
    <div class="chart" id="lineChart"></div>
    <div class="legend">
      <span><i class="swatch" style="background:var(--series-1)"></i>累计终态</span>
      <span><i class="swatch" style="background:var(--series-3)"></i>累计 passed</span>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <h2>每 15 分钟吞吐（近 6 小时）</h2>
      <p class="hint">柱子高度=该时段落账终态数；深色部分为 passed</p>
      <div class="chart" id="barChart"></div>
      <div class="legend">
        <span><i class="swatch" style="background:var(--series-1)"></i>passed</span>
        <span><i class="swatch" style="background:var(--series-2)"></i>其他终态</span>
      </div>
    </div>
    <div class="card">
      <h2>终态构成</h2>
      <p class="hint">百分比按当前全部终态计</p>
      <div class="chart" id="donutChart"></div>
      <div class="legend" id="donutLegend"></div>
      <details>
        <summary>数据表</summary>
        <table id="catTable"></table>
      </details>
    </div>
  </div>
</div>
<script>
const CAT_COLORS = ["--series-1","--series-2","--series-3","--series-4",
                    "--series-5","--series-6","--series-7","--series-8"];
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const fmt = (n) => n.toLocaleString("zh-CN");

function el(tag, attrs = {}, text) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

function tooltip(container) {
  const tip = document.createElement("div");
  tip.className = "tooltip";
  container.appendChild(tip);
  return {
    show(html, x, y) {
      tip.innerHTML = html;
      tip.style.opacity = 1;
      const box = container.getBoundingClientRect();
      const w = tip.offsetWidth;
      tip.style.left = Math.min(Math.max(8, x - w / 2), box.width - w - 8) + "px";
      tip.style.top = Math.max(0, y - tip.offsetHeight - 10) + "px";
    },
    hide() { tip.style.opacity = 0; }
  };
}

function drawLine(container, data) {
  container.innerHTML = "";
  const W = 900, H = 280, m = {l: 46, r: 16, t: 12, b: 30};
  const svg = el("svg", {viewBox: `0 0 ${W} ${H}`, role: "img",
                         "aria-label": "累计终态与累计 passed 曲线"});
  const t = data.series.t, term = data.series.terminals, pass = data.series.passed;
  if (!t.length) {
    container.innerHTML = '<div class="empty">还没有终态数据</div>';
    return;
  }
  const t0 = t[0], t1 = Math.max(t[t.length - 1], t0 + 60);
  const maxY = Math.max(term[term.length - 1], 10);
  const x = (v) => m.l + (v - t0) / (t1 - t0) * (W - m.l - m.r);
  const y = (v) => H - m.b - v / maxY * (H - m.t - m.b);

  for (let i = 0; i <= 4; i++) {
    const val = maxY * i / 4, yy = y(val);
    svg.appendChild(el("line", {x1: m.l, x2: W - m.r, y1: yy, y2: yy,
                                stroke: css("--grid"), "stroke-width": 1}));
    svg.appendChild(el("text", {x: m.l - 8, y: yy + 4, "text-anchor": "end",
                                fill: css("--text-muted"), "font-size": 11}, Math.round(val)));
  }
  const span = t1 - t0, step = Math.max(3600, Math.ceil(span / 6 / 3600) * 3600);
  for (let tt = Math.ceil(t0 / step) * step; tt <= t1; tt += step) {
    const d = new Date(tt * 1000);
    svg.appendChild(el("text", {x: x(tt), y: H - 8, "text-anchor": "middle",
                                fill: css("--text-muted"), "font-size": 11},
                          d.toLocaleTimeString("zh-CN", {hour: "2-digit", minute: "2-digit"})));
  }
  const path = (arr) => arr.map((v, i) => `${i ? "L" : "M"}${x(t[i]).toFixed(1)},${y(v).toFixed(1)}`).join("");
  svg.appendChild(el("path", {d: path(term) + `L${x(t1)},${y(term[term.length-1])}L${x(t1)},${y(0)}L${x(t0)},${y(0)}Z`,
                              fill: css("--series-1"), "fill-opacity": 0.07}));
  svg.appendChild(el("path", {d: path(term), fill: "none", stroke: css("--series-1"),
                              "stroke-width": 2, "stroke-linejoin": "round"}));
  svg.appendChild(el("path", {d: path(pass), fill: "none", stroke: css("--series-3"),
                              "stroke-width": 2, "stroke-linejoin": "round"}));
  const cross = el("line", {y1: m.t, y2: H - m.b, stroke: css("--text-muted"),
                            "stroke-width": 1, "stroke-dasharray": "3 3", opacity: 0});
  svg.appendChild(cross);
  container.appendChild(svg);
  const tip = tooltip(container);
  const hit = el("rect", {x: m.l, y: m.t, width: W - m.l - m.r, height: H - m.t - m.b,
                          fill: "transparent"});
  svg.appendChild(hit);
  hit.addEventListener("mousemove", (ev) => {
    const box = svg.getBoundingClientRect();
    const px = (ev.clientX - box.left) / box.width * W;
    const tv = t0 + (px - m.l) / (W - m.l - m.r) * (t1 - t0);
    let i = 0;
    while (i + 1 < t.length && t[i + 1] <= tv) i++;
    cross.setAttribute("x1", x(t[i])); cross.setAttribute("x2", x(t[i]));
    cross.setAttribute("opacity", 0.6);
    const d = new Date(t[i] * 1000);
    tip.show(`<b>${d.toLocaleTimeString("zh-CN", {hour: "2-digit", minute: "2-digit"})}</b><br>
              累计终态 <b>${fmt(term[i])}</b><br>累计 passed <b>${fmt(pass[i])}</b>`,
             ev.clientX - box.left, ev.clientY - box.top);
  });
  hit.addEventListener("mouseleave", () => { cross.setAttribute("opacity", 0); tip.hide(); });
}

function drawBars(container, data) {
  container.innerHTML = "";
  const W = 640, H = 200, m = {l: 36, r: 8, t: 8, b: 26};
  const b = data.buckets;
  const maxY = Math.max(1, ...b.map(d => d.terminals));
  const svg = el("svg", {viewBox: `0 0 ${W} ${H}`, role: "img",
                         "aria-label": "每 15 分钟终态吞吐"});
  for (let i = 0; i <= 2; i++) {
    const val = Math.round(maxY * i / 2), yy = H - m.b - (H - m.t - m.b) * i / 2;
    svg.appendChild(el("line", {x1: m.l, x2: W - m.r, y1: yy, y2: yy,
                                stroke: css("--grid"), "stroke-width": 1}));
    svg.appendChild(el("text", {x: m.l - 6, y: yy + 4, "text-anchor": "end",
                                fill: css("--text-muted"), "font-size": 11}, val));
  }
  const bw = (W - m.l - m.r) / b.length;
  const tip = tooltip(container);
  container.appendChild(svg);
  b.forEach((d, i) => {
    const h = (H - m.t - m.b) * (d.terminals / maxY);
    const x0 = m.l + i * bw + 1;
    const yTop = H - m.b - h;
    const other = d.terminals - d.passed;
    if (d.passed) {
      const hp = (H - m.t - m.b) * (d.passed / maxY);
      svg.appendChild(el("rect", {x: x0, y: H - m.b - hp, width: bw - 2, height: hp,
                                  rx: 2, fill: css("--series-1")}));
    }
    if (other > 0) {
      const ho = (H - m.t - m.b) * (other / maxY);
      svg.appendChild(el("rect", {x: x0, y: yTop, width: bw - 2, height: Math.max(0, ho - 1),
                                  rx: 2, fill: css("--series-2")}));
    }
    if (!d.terminals) return;
    const hit = el("rect", {x: x0, y: m.t, width: bw - 2, height: H - m.t - m.b,
                            fill: "transparent"});
    svg.appendChild(hit);
    hit.addEventListener("mousemove", (ev) => {
      const box = svg.getBoundingClientRect();
      const t = new Date(d.t0 * 1000);
      tip.show(`<b>${t.toLocaleTimeString("zh-CN", {hour: "2-digit", minute: "2-digit"})}</b>
                – ${new Date((d.t0 + 900) * 1000).toLocaleTimeString("zh-CN", {hour: "2-digit", minute: "2-digit"})}<br>
               终态 <b>${d.terminals}</b>（passed <b>${d.passed}</b>）`,
             ev.clientX - box.left, ev.clientY - box.top);
    });
    hit.addEventListener("mouseleave", () => tip.hide());
  });
  for (let i = 0; i < b.length; i += 4) {
    const t = new Date(b[i].t0 * 1000);
    svg.appendChild(el("text", {x: m.l + i * bw + bw / 2, y: H - 8, "text-anchor": "middle",
                                fill: css("--text-muted"), "font-size": 11},
                          t.toLocaleTimeString("zh-CN", {hour: "2-digit", minute: "2-digit"})));
  }
}

function drawDonut(container, legend, data) {
  container.innerHTML = ""; legend.innerHTML = "";
  const cats = data.categories;
  const total = cats.reduce((s, c) => s + c.count, 0);
  if (!total) { container.innerHTML = '<div class="empty">还没有终态数据</div>'; return; }
  const S = 190, R = 82, r = 54, cx = S / 2, cy = S / 2;
  const svg = el("svg", {viewBox: `0 0 ${S} ${S}`, width: S, height: S, role: "img",
                         "aria-label": "终态构成环形图"});
  let angle = -Math.PI / 2;
  const tip = tooltip(container);
  container.appendChild(svg);
  cats.forEach((c, i) => {
    const frac = c.count / total;
    const end = angle + frac * Math.PI * 2;
    const gap = Math.min(0.03, frac * Math.PI * 2 * 0.15);
    const a0 = angle + gap / 2, a1 = end - gap / 2;
    if (a1 > a0) {
      const large = a1 - a0 > Math.PI ? 1 : 0;
      const p = (rad, a) => `${(cx + rad * Math.cos(a)).toFixed(2)},${(cy + rad * Math.sin(a)).toFixed(2)}`;
      const d = `M${p(R, a0)}A${R},${R} 0 ${large} 1 ${p(R, a1)}L${p(r, a1)}A${r},${r} 0 ${large} 0 ${p(r, a0)}Z`;
      const arc = el("path", {d, fill: css(CAT_COLORS[i % 8]), stroke: css("--surface-1"),
                              "stroke-width": 2});
      arc.addEventListener("mousemove", (ev) => {
        const box = container.getBoundingClientRect();
        tip.show(`<b>${c.label}</b><br>${fmt(c.count)} 题 · ${(frac * 100).toFixed(1)}%`,
                 ev.clientX - box.left, ev.clientY - box.top);
      });
      arc.addEventListener("mouseleave", () => tip.hide());
      svg.appendChild(arc);
    }
    angle = end;
  });
  svg.appendChild(el("text", {x: cx, y: cy - 2, "text-anchor": "middle",
                              fill: css("--text-primary"), "font-size": 22, "font-weight": 600},
                        fmt(total)));
  svg.appendChild(el("text", {x: cx, y: cy + 16, "text-anchor": "middle",
                              fill: css("--text-muted"), "font-size": 11}, "终态题数"));

  cats.forEach((c, i) => {
    const span = document.createElement("span");
    span.innerHTML = `<i class="swatch" style="background:${css(CAT_COLORS[i % 8])}"></i>
                      ${c.label} ${(c.count / total * 100).toFixed(1)}%`;
    legend.appendChild(span);
  });
  let rows = "<tr><th>类别</th><th>数量</th><th>占比</th></tr>";
  cats.forEach((c) => {
    rows += `<tr><td>${c.label}</td><td>${fmt(c.count)}</td>
             <td>${(c.count / total * 100).toFixed(1)}%</td></tr>`;
  });
  document.getElementById("catTable").innerHTML = rows;
}

function kpis(d) {
  const hour = d.speed.last_hour, prev = d.speed.prev_hour;
  const delta = hour.terminals - prev.terminals;
  const arrow = delta === 0 ? "持平" : (delta > 0 ? `+${delta}` : `${delta}`);
  const tiles = [
    ["passed", fmt(d.passed), `目标 800 · 队列 ${fmt(d.cohort)}`],
    ["B 成功率", d.rate_b.pct + "%", `分母 ${fmt(d.rate_b.denominator)}（含基础设施错误）`],
    ["进行中", fmt(d.in_progress_total), Object.entries(d.in_progress)
        .map(([k, v]) => `${k} ${v}`).join(" · ") || "—"],
    ["近 1 小时终态", fmt(hour.terminals), `上一小时 ${prev.terminals}（${arrow}）`],
    ["近 1 小时 passed", fmt(hour.passed), `上一小时 ${prev.passed}`],
    ["磁盘 /nvme", (d.disk.nvme_free_gb ?? "?") + "G", "低于 150G 需暂停调度"],
  ];
  document.getElementById("kpis").innerHTML = tiles.map(([label, value, sub]) =>
    `<div class="tile"><div class="label">${label}</div>
     <div class="value">${value}</div><div class="sub">${sub}</div></div>`).join("");
}

async function refresh() {
  const res = await fetch("/api/stats", {cache: "no-store"});
  const d = await res.json();
  kpis(d);
  drawLine(document.getElementById("lineChart"), d);
  drawBars(document.getElementById("barChart"), d);
  drawDonut(document.getElementById("donutChart"),
            document.getElementById("donutLegend"), d);
  document.getElementById("meta").textContent =
    `队列 ${fmt(d.cohort)} 题 · 终态 ${fmt(d.terminal)} · 进行中 ${fmt(d.in_progress_total)}`;
  document.getElementById("stamp").textContent =
    "更新于 " + new Date(d.generated_at * 1000).toLocaleTimeString("zh-CN");
}
refresh();
setInterval(refresh, 15000);
window.addEventListener("resize", () => refresh());
</script>
</body>
</html>
"""


class Server(ThreadingHTTPServer):
    """HTTP server that never resolves its own hostname.

    ``HTTPServer.server_bind`` calls ``socket.getfqdn()``; on this host reverse
    lookups stall for minutes under container churn, which left the dashboard
    bound but unreachable.
    """

    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self):
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


def make_handler(results: Path, fresh: Path | None, since: float = 0.0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # keep the terminal quiet
            pass

        def do_GET(self):
            if self.path.startswith("/api/stats"):
                body = json.dumps(stats(results, fresh, since), ensure_ascii=False).encode()
                ctype = "application/json; charset=utf-8"
            elif self.path in ("/", "/index.html"):
                body = PAGE.encode()
                ctype = "text/html; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("results/batch-01"))
    parser.add_argument("--fresh-file", type=Path,
                        default=Path("samples/batch-01/fresh-todo.txt"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--since", default=None,
                        help="only count terminal records after this UTC time "
                             "(default: run_start from .monitor-snapshot.json)")
    args = parser.parse_args()
    results = args.results.resolve()
    fresh = args.fresh_file.resolve() if args.fresh_file else None
    since = 0.0
    stamp = args.since
    if not stamp:
        snapshot = load(results / ".monitor-snapshot.json")
        stamp = snapshot.get("run_start")
    if stamp:
        text = stamp.strip().replace("Z", "")
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
            try:
                since = time.mktime(time.strptime(text, fmt))
                break
            except ValueError:
                continue
    server = Server((args.host, args.port), make_handler(results, fresh, since))
    print(f"progress dashboard: http://localhost:{args.port}/  "
          f"(listening on {args.host}; results={results})", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())