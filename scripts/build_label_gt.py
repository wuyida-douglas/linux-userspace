#!/usr/bin/env python3
"""Independent multi-agent GT reviews, then adjudicate every disagreement."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.common import ROOT, load_env, read_jsonl, timestamp, write_json, write_jsonl
from pipeline.labeling import (ADJUDICATE_PROMPT, JsonLabeler, batch_id, compact_row,
                               compact_text, completed_batches, gt_prompt, gt_specs,
                               submit_batches)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/label-bench-v1/sample150.jsonl")
    parser.add_argument("--output", type=Path, default=ROOT / "results/label-gt-v1")
    parser.add_argument("--model", default="glm-5.3")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--retries", type=int, default=7)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--env", type=Path, default=Path("/nvme/wuyida/env"))
    args = parser.parse_args()
    rows = list(read_jsonl(args.input))
    labeler = JsonLabeler(load_env(args.env), model=args.model, max_tokens=args.max_tokens)
    specs = gt_specs(rows)
    specs = [(kind, name, gt_prompt(kind), items) for kind, name, items in specs]
    submit_batches(args.output, specs, labeler, args.workers, args.retries)
    done = completed_batches(args.output)
    votes = {row["instance_id"]: {} for row in rows}
    for spec in specs:
        kind, name, _, items = spec
        role = kind.removeprefix("gt-")
        votes[items[0]["instance_id"]][role] = done[name]["result"]["labels"][0]
    adjudication_specs = []
    for row in rows:
        instance_id = row["instance_id"]
        role_votes = votes[instance_id]
        # Unanimous decisions retain all three independent evidence trails;
        # only genuinely disputed items require extra API cost.
        if len({vote["label"] for vote in role_votes.values()}) == 1:
            continue
        original = compact_row(row, include_evidence=True)
        item = {"instance_id": instance_id,
                "original_metadata": original,
                "independent_reviews": role_votes}
        name = batch_id([item]) + "-adjudication"
        adjudication_specs.append(("adjudication", name, ADJUDICATE_PROMPT, [item]))
    print(f"independent reviews complete; disputed={len(adjudication_specs)} unanimous={len(rows)-len(adjudication_specs)}", flush=True)
    submit_batches(args.output, adjudication_specs, labeler, args.workers, args.retries)
    done = completed_batches(args.output)
    final = []
    sample_path = args.input.resolve()
    dev_ids = set()
    if sample_path.with_name("dev100.jsonl").is_file():
        dev_ids = {row["instance_id"] for row in read_jsonl(sample_path.with_name("dev100.jsonl"))}
    for row in rows:
        instance_id = row["instance_id"]
        role_votes = votes[instance_id]
        labels = {vote["label"] for vote in role_votes.values()}
        if len(labels) == 1:
            label = role_votes["inclusive"]["label"]
            confidence = sum(vote["confidence"] for vote in role_votes.values()) / 3
            reason = "Unanimous independent reviews: " + " | ".join(
                f"{role}: {vote['reason']}" for role, vote in role_votes.items())
            agreement = "unanimous"
            adjudicated = False
        else:
            name = batch_id([{"instance_id": instance_id,
                              "original_metadata": compact_row(row, include_evidence=True),
                              "independent_reviews": role_votes}]) + "-adjudication"
            result = done[name]["result"]
            label, confidence, reason, agreement = (result["label"], result["confidence"],
                                                     result["reason"], result["agreement"])
            adjudicated = True
        final.append({"instance_id": instance_id, "repo": row["repo"],
                      "title": (row.get("vulnerability") or {}).get("title"),
                      "label": label, "confidence": confidence, "reason": reason,
                      "agreement": agreement, "adjudicated": adjudicated,
                      "independent_votes": role_votes,
                      "split": "dev" if instance_id in dev_ids else "holdout"})
    write_jsonl(args.output / "gt.jsonl", final)
    report = {"sample": str(args.input), "count": len(final),
              "labels": dict(Counter(item["label"] for item in final)),
              "agreement": dict(Counter(item["agreement"] for item in final)),
              "adjudicated": sum(item["adjudicated"] for item in final),
              "review_roles": ["inclusive", "strict", "boundary"],
              "model": args.model, "created_at": timestamp(),
              "limitation": "Metadata-review GT, not proof of buildable tasks or final exploit delivery."}
    write_json(args.output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
