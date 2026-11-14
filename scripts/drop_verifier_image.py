#!/usr/bin/env python3
"""Drop the dedicated verifier image from already-exported bundles.

Harbor's separate verifier mode falls back to ``[environment].docker_image``
when ``[verifier.environment]`` is absent, so the shared agent image serves the
verifier control container too. New exports no longer ship
``shared-images/verifier.tar.gz``; this migrates the bundles exported before
that change:

* remove the ``[verifier.environment]`` section from ``task.toml``;
* remove the ``role = "verifier"`` entry from ``image-lock.json``;
* delete the shared verifier archive and its manifests at the root.

    python3 scripts/drop_verifier_image.py --root harbor_export/... --dry-run
    python3 scripts/drop_verifier_image.py --root harbor_export/...
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SECTION = "[verifier.environment]"


def strip_section(text: str) -> tuple[str, bool]:
    lines = text.splitlines(True)
    output: list[str] = []
    skipping = False
    removed = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            skipping = stripped == SECTION
            if skipping:
                removed = True
                continue
        if skipping:
            continue
        output.append(line)
    return "".join(output), removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    toml_changed = lock_changed = 0
    bundles = 0
    for toml in sorted(root.glob("*/harbor-runtime-profile/task.toml")):
        bundles += 1
        text = toml.read_text(encoding="utf-8")
        new_text, removed = strip_section(text)
        if removed:
            toml_changed += 1
            if not args.dry_run:
                toml.write_text(new_text, encoding="utf-8")
        lock = toml.parent.parent / "image-lock.json"
        if not lock.is_file():
            continue
        try:
            value = json.loads(lock.read_text(encoding="utf-8"))
        except ValueError:
            continue
        images = value.get("images") or []
        kept = [item for item in images if item.get("role") != "verifier"]
        if len(kept) != len(images):
            lock_changed += 1
            if not args.dry_run:
                value["images"] = kept
                lock.write_text(json.dumps(value, ensure_ascii=False, indent=1) + "\n",
                                encoding="utf-8")
    shared = root / "shared-images"
    shared_removed = []
    for name in ("verifier.tar.gz", "verifier.tar.manifest.json", "verifier.manifest.json"):
        path = shared / name
        if path.is_file():
            shared_removed.append(name)
            if not args.dry_run:
                path.unlink()
    print(f"bundles={bundles} toml_changed={toml_changed} lock_changed={lock_changed} "
          f"shared_removed={shared_removed} dry_run={args.dry_run}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())