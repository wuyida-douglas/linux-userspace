#!/usr/bin/env python3
"""Recover only missing production labels, validate exact coverage, and export.

The production ten-item results remain immutable. Small recovery batches live
in a separate directory and are merged by instance_id only after validation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.common import ROOT, load_env, read_jsonl, sha256, timestamp, write_json, write_jsonl
from pipeline.labeling import (LABEL_PROMPT_V1, JsonLabeler, batch_id, compact_row,
                               flatten_classification, process_pending)


def load_complete(directory: Path, input_ids: set[str]) -> dict[str, dict]:
    labels = flatten_classification(directory)
    unexpected = set(labels) - input_ids
    if unexpected:
        raise ValueError(f"{directory}: {len(unexpected)} labels are not in the production input")
    for instance_id, label in labels.items():
        if label.get("label") not in {"keep", "reject"}:
            raise ValueError(f"invalid label for {instance_id}")
    return labels


def load_recoveries(directories: list[Path], input_ids: set[str]) -> dict[str, dict]:
    recovered: dict[str, dict] = {}
    for directory in directories:
        if not (directory / "batches").exists():
            continue
        batch_labels = load_complete(directory, input_ids)
        duplicate = set(recovered) & set(batch_labels)
        if duplicate:
            raise ValueError(f"duplicate IDs across recovery directories: {len(duplicate)}")
        recovered.update(batch_labels)
    return recovered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/minimal-exclusions-v1/candidates.jsonl")
    parser.add_argument("--production", type=Path, default=ROOT / "results/label-production-v1")
    parser.add_argument("--output", type=Path, default=ROOT / "results/label-production-recovery-v1")
    parser.add_argument("--also-read", type=Path, nargs="*", default=[],
                        help="completed prior recovery directories to merge without re-requesting")
    parser.add_argument("--model", default="glm-5.3")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--batch-size", type=int, choices=(1, 2), default=2)
    parser.add_argument("--retries", type=int, default=7)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--env", type=Path, default=Path("/nvme/wuyida/env"))
    parser.add_argument("--finalize", action="store_true", help="export only after exact complete coverage")
    args = parser.parse_args()
    if not 1 <= args.workers <= 20 or args.retries < 1 or args.max_tokens < 512:
        parser.error("workers must be 1..20, retries positive and max-tokens >= 512")
    rows = list(read_jsonl(args.input))
    ids = [row["instance_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("production input IDs must be unique")
    input_ids = set(ids)
    config_path = args.production / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    expected_config = {
        "input": str(args.input.resolve()), "input_sha256": sha256(args.input),
        "input_count": len(rows), "model": args.model,
        "prompt_sha256": hashlib.sha256(LABEL_PROMPT_V1.encode()).hexdigest(),
    }
    for key, expected in expected_config.items():
        if config.get(key) != expected:
            raise ValueError(f"production configuration mismatch for {key}")
    recovery_directories = list(dict.fromkeys(path.resolve() for path in
                                              [*args.also_read, args.output]))
    labels = load_complete(args.production, input_ids)
    recovered = load_recoveries(recovery_directories, input_ids)
    overlap = set(labels) & set(recovered)
    if overlap:
        raise ValueError(f"production/recovery overlap: {len(overlap)} IDs")
    labels.update(recovered)
    missing = input_ids - set(labels)
    print(json.dumps({"production_labels": len(labels) - len(recovered),
                      "already_recovered": len(recovered), "missing": len(missing)}, indent=2), flush=True)
    if missing:
        row_by_id = {row["instance_id"]: row for row in rows}
        # Retain failed production groups to make diagnostics traceable. On a
        # resumed recovery, skip its already committed IDs and re-split the rest.
        failed_groups: dict[str, list[str]] = {}
        for path in sorted((args.production / "batches").glob("*.failed.json")):
            failure = json.loads(path.read_text(encoding="utf-8"))
            failed_groups[failure["batch_id"]] = [
                item for item in failure.get("instance_ids", []) if item in missing]
        assigned = {item for group in failed_groups.values() for item in group}
        if len(assigned) != len(set(assigned)):
            raise ValueError("duplicate IDs in failed production diagnostics")
        for instance_id in sorted(missing - assigned):
            failed_groups["ungrouped-" + hashlib.sha256(instance_id.encode()).hexdigest()[:16]] = [instance_id]
        specs = []
        manifest = []
        for parent, group in failed_groups.items():
            for index in range(0, len(group), args.batch_size):
                items = [compact_row(row_by_id[item]) for item in group[index:index + args.batch_size]]
                if not items:
                    continue
                name = batch_id(items)
                specs.append(("classification-v1", name, LABEL_PROMPT_V1, items))
                manifest.append({"recovery_batch_id": name, "production_batch_id": parent,
                                 "instance_ids": [item["instance_id"] for item in items]})
        recovery_config = {
            "schema_version": "metadata-label-recovery-v1", "input": str(args.input.resolve()),
            "input_sha256": expected_config["input_sha256"], "production": str(args.production.resolve()),
            "model": args.model, "thinking": "disabled", "max_tokens": args.max_tokens,
            "batch_size": args.batch_size, "workers": args.workers,
            "prompt_sha256": expected_config["prompt_sha256"], "prompt": LABEL_PROMPT_V1,
            "requested_ids": sorted(missing), "batches": manifest, "created_at": timestamp(),
        }
        previous_path = args.output / "recovery-config.json"
        if previous_path.exists():
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
            for key in ("input_sha256", "production", "model", "batch_size", "prompt_sha256"):
                if previous.get(key) != recovery_config[key]:
                    raise ValueError(f"cannot resume recovery with changed {key}")
        write_json(previous_path, recovery_config)
        labeler = JsonLabeler(load_env(args.env), model=args.model, max_tokens=args.max_tokens,
                              thinking_enabled=False)
        process_pending(args.output, specs, labeler, workers=args.workers, retries=args.retries)
        recovered = load_recoveries(recovery_directories, input_ids)
        overlap = (set(labels) - set(recovered)) & set(recovered)
        if overlap:
            raise ValueError("recovery introduced duplicate production IDs")
        labels.update(recovered)
        missing = input_ids - set(labels)
    status = {"input_count": len(rows), "covered": len(labels), "missing_count": len(missing),
              "missing_ids": sorted(missing), "production": str(args.production.resolve()),
              "recovery": str(args.output.resolve()),
              "recovery_directories": [str(path) for path in recovery_directories],
              "complete": not missing, "updated_at": timestamp()}
    write_json(args.output / "coverage.json", status)
    print(json.dumps({key: value for key, value in status.items() if key != "missing_ids"}, indent=2), flush=True)
    if missing:
        return 1
    if not args.finalize:
        return 0
    prompt_hash = expected_config["prompt_sha256"]
    labeled = []
    for row in rows:
        label = labels[row["instance_id"]]
        labeled.append(row | {"metadata_label": {
            "schema_version": "metadata-routing-binary-v1", "label": label["label"],
            "confidence": label["confidence"], "reason": label["reason"],
            "batch_id": label["batch_id"], "model": args.model, "prompt_sha256": prompt_hash,
        }})
    write_jsonl(args.production / "labeled.jsonl", labeled)
    kept = [row for row in labeled if row["metadata_label"]["label"] == "keep"]
    rejected = [row for row in labeled if row["metadata_label"]["label"] == "reject"]
    write_jsonl(args.production / "candidates-kept.jsonl", kept)
    write_jsonl(args.production / "candidates-rejected.jsonl", rejected)
    report = {"input": str(args.input.resolve()), "input_count": len(rows),
              "covered": len(labels), "missing": 0, "model": args.model,
              "production_batch_size": 10, "production_thinking": "disabled",
              "recovery_batch_size": args.batch_size, "recovery_thinking": "disabled",
              "recovery_labels": len(recovered),
              "recovery_directories": [str(path) for path in recovery_directories],
              "prompt_sha256": prompt_hash,
              "labels": dict(Counter(row["metadata_label"]["label"] for row in labeled)),
              "kept_path": str((args.production / "candidates-kept.jsonl").resolve()),
              "rejected_path": str((args.production / "candidates-rejected.jsonl").resolve()),
              "recovery_coverage": str((args.output / "coverage.json").resolve()),
              "completed_at": timestamp()}
    write_json(args.production / "report.json", report)
    write_json(args.production / "recovery-report.json", status)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
