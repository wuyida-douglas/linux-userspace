#!/usr/bin/env python3
"""Refresh the custom verifier inside already-exported Harbor bundles.

Every exported task ships a self-contained ``harbor-runtime-profile/bin/`` with
the pass2fail verifier. When the verifier changes, bundles exported before the
change keep the old logic, so the same delivery behaves differently depending
on when it was exported. This copies the current verifier files into every
bundle and records the before/after hashes.

    python3 scripts/refresh_exported_verifier.py --root harbor_export/... --dry-run
    python3 scripts/refresh_exported_verifier.py --root harbor_export/...

Only files that actually differ are rewritten. Helper modules travel with the
verifier (docker_ipam.py changed several times during the batch), so they are
refreshed together; a missing file is reported instead.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER_FILES = ("pass2fail_verifier.py", "legacy_pass2fail_verifier.py",
                  "docker_ipam.py", "pristine_binds.py", "task_contract.py")


def digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True,
                        help="published root, e.g. harbor_export/20261111-production")
    parser.add_argument("--pipeline", type=Path, default=ROOT / "pipeline")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    root: Path = args.root.resolve()
    source = args.pipeline.resolve()
    current = {name: digest(source / name) for name in VERIFIER_FILES}
    profiles = sorted(root.glob("*/harbor-runtime-profile/bin/pass2fail_verifier.py"))
    updated = unchanged = helper_mismatch = 0
    tasks_updated: list[dict[str, str]] = []
    for profile in profiles:
        task_dir = profile.parents[2]
        task = task_dir.name
        changed = {}
        for name in VERIFIER_FILES:
            target = profile.parent / name
            before = digest(target)
            after = current[name]
            if before == after:
                continue
            changed[name] = before[:12] + "->" + after[:12]
            if not args.dry_run:
                shutil.copy2(source / name, target)
        missing = [name for name in VERIFIER_FILES
                   if not (profile.parent / name).is_file()]
        if missing:
            helper_mismatch += 1
            changed["missing"] = ",".join(missing)
        if changed:
            updated += 1
            tasks_updated.append({"task": task, "changes": changed})
        else:
            unchanged += 1
    print(f"bundles={len(profiles)} updated={updated} unchanged={unchanged} "
          f"helper_mismatch={helper_mismatch} dry_run={args.dry_run}")
    if not args.dry_run:
        report = root / "verifier-refresh-report.json"
        report.write_text(json.dumps({
            "source": str(source),
            "verifier_sha256": current,
            "updated": updated,
            "unchanged": unchanged,
            "helper_mismatch": helper_mismatch,
            "tasks": tasks_updated,
        }, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print("report:", report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())