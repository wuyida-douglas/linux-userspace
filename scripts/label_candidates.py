#!/usr/bin/env python3
"""Run resumable ten-instance binary metadata labeling and evaluate optional GT."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.common import ROOT, load_env, read_jsonl, sha256, timestamp, write_json, write_jsonl
from pipeline.labeling import (LABEL_PROMPT_V1, JsonLabeler, classification_specs,
                               compact_row, flatten_classification, submit_batches)


def metrics(pairs: list[dict]) -> dict:
    counts = Counter()
    for pair in pairs:
        predicted, actual = pair["prediction"]["label"], pair["gt"]["label"]
        counts["tp" if predicted == actual == "keep" else
               "tn" if predicted == actual == "reject" else
               "fp" if predicted == "keep" else "fn"] += 1
    total = len(pairs)
    correct = counts["tp"] + counts["tn"]
    return {"n": total, **dict(counts),
            "accuracy": correct / total if total else None,
            "keep_recall": counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else None,
            "keep_precision": counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else None,
            "reject_recall": counts["tn"] / (counts["tn"] + counts["fp"]) if counts["tn"] + counts["fp"] else None,
            "note": "Positive means merits source/patch routing, not proven buildability."}


def evaluate(labeled: dict[str, dict], gt_path: Path) -> dict:
    pairs = []
    for gt in read_jsonl(gt_path):
        if gt["instance_id"] in labeled:
            pairs.append({"gt": gt, "prediction": labeled[gt["instance_id"]]})
    dev = [pair for pair in pairs if pair["gt"].get("split") == "dev"]
    holdout = [pair for pair in pairs if pair["gt"].get("split") == "holdout"]
    errors = [{"instance_id": pair["gt"]["instance_id"], "repo": pair["gt"].get("repo"),
               "title": pair["gt"].get("title"), "gt": pair["gt"]["label"],
               "gt_reason": pair["gt"].get("reason"), "prediction": pair["prediction"]["label"],
               "prediction_reason": pair["prediction"]["reason"], "split": pair["gt"].get("split")}
              for pair in pairs if pair["gt"]["label"] != pair["prediction"]["label"]]
    return {"all": metrics(pairs), "dev": metrics(dev), "holdout": metrics(holdout),
            "error_count": len(errors), "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/minimal-exclusions-v1/candidates.jsonl")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gt", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--model", default="glm-5.3")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--retries", type=int, default=7)
    parser.add_argument("--thinking", choices=("enabled", "disabled"), default="enabled")
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--env", type=Path, default=Path("/nvme/wuyida/env"))
    args = parser.parse_args()
    if args.batch_size != 10:
        parser.error("this production configuration deliberately uses exactly 10 records per request")
    if args.limit is not None and args.limit < 1:
        parser.error("limit must be positive")
    rows = list(read_jsonl(args.input))
    if args.limit:
        rows = rows[:args.limit]
    ids = [row["instance_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("input instance_ids must be unique")
    prompt_hash = hashlib.sha256(LABEL_PROMPT_V1.encode()).hexdigest()
    config = {"input": str(args.input.resolve()), "input_sha256": sha256(args.input),
              "input_count": len(rows), "limit": args.limit, "model": args.model,
              "batch_size": args.batch_size, "workers": args.workers,
              "prompt_sha256": prompt_hash, "prompt": LABEL_PROMPT_V1,
              "input_digest": hashlib.sha256("\n".join(ids).encode()).hexdigest()}
    config_path = args.output / "config.json"
    if config_path.exists():
        previous = json.loads(config_path.read_text(encoding="utf-8"))
        for key in ("input_sha256", "input_count", "input_digest", "batch_size", "model", "prompt_sha256"):
            if previous.get(key) != config[key]:
                raise ValueError(f"cannot resume with changed {key}; choose a new output directory")
    # Preserve completed exact-ID batches even when resuming with a validated
    # generation configuration. New batches and the final report record the
    # actual configuration; no claim that the old attempts were no-think.
    config["thinking"] = args.thinking
    config["max_tokens"] = args.max_tokens
    config["generation_config_updated_at"] = timestamp()
    write_json(config_path, config)
    labeler = JsonLabeler(load_env(args.env), model=args.model, max_tokens=args.max_tokens,
                          thinking_enabled=args.thinking == "enabled")
    specs = classification_specs(rows, LABEL_PROMPT_V1, args.batch_size)
    submit_batches(args.output, specs, labeler, args.workers, args.retries)
    labels = flatten_classification(args.output)
    if set(labels) != set(ids):
        raise ValueError("labeled coverage differs from exact input IDs")
    labeled = []
    for row in rows:
        label = labels[row["instance_id"]]
        labeled.append(row | {"metadata_label": {"schema_version": "metadata-routing-binary-v1",
                                                 "label": label["label"], "confidence": label["confidence"],
                                                 "reason": label["reason"], "batch_id": label["batch_id"],
                                                 "model": args.model, "prompt_sha256": prompt_hash}})
    write_jsonl(args.output / "labeled.jsonl", labeled)
    write_jsonl(args.output / "candidates-kept.jsonl", [row for row in labeled if row["metadata_label"]["label"] == "keep"])
    write_jsonl(args.output / "candidates-rejected.jsonl", [row for row in labeled if row["metadata_label"]["label"] == "reject"])
    batches = list((args.output / "batches").glob("batch-*.json"))
    usage = Counter()
    for path in batches:
        value = json.loads(path.read_text(encoding="utf-8"))
        for key, count in (value.get("usage") or {}).items():
            if isinstance(count, (int, float)) and not isinstance(count, bool):
                usage[key] += count
    confidence = [row["metadata_label"]["confidence"] for row in labeled]
    confidence.sort()
    report = {"input": str(args.input), "input_count": len(rows), "model": args.model,
              "batch_size": args.batch_size, "batch_count": math.ceil(len(rows) / args.batch_size),
              "thinking": args.thinking, "max_tokens": args.max_tokens,
              "prompt_sha256": prompt_hash, "labels": dict(Counter(row["metadata_label"]["label"] for row in labeled)),
              "kept_path": str(args.output / "candidates-kept.jsonl"), "usage": dict(usage),
              "low_confidence": {"below_0.6": sum(value < 0.6 for value in confidence),
                                 "below_0.7": sum(value < 0.7 for value in confidence)},
              "completed_at": timestamp()}
    if args.gt:
        report["evaluation"] = evaluate(labels, args.gt)
        write_json(args.output / "evaluation.json", report["evaluation"])
    write_json(args.output / "report.json", report)
    print(json.dumps({key: value for key, value in report.items() if key != "evaluation"}, ensure_ascii=False, indent=2))
    if args.gt:
        print(json.dumps({key: value for key, value in report["evaluation"].items() if key != "errors"},
                         ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
