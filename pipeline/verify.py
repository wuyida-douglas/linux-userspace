"""Execute the shipped pass2fail verifier; do not trust a synthesized report."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from .pass2fail_verifier import fresh_verify
from .task_contract import load_task


def validate_report(value: Any) -> None:
    if not isinstance(value, dict) or value.get("schema_version") != 2:
        raise ValueError("report schema_version must be 2")
    if not isinstance(value.get("success"), bool) or value.get("reward") not in {0.0, 1.0}:
        raise ValueError("invalid pass2fail success/reward")
    if value.get("status") == "miss":
        if value["success"] or value["reward"] != 0.0:
            raise ValueError("a missing submission cannot succeed")
        return
    if value.get("branch") not in {"SVC-EXPLOIT", "FILE-EXPLOIT", "FILE-POV"}:
        raise ValueError("invalid delivery branch")
    vulnerable, fixed = value.get("vulnerable"), value.get("fixed")
    if not isinstance(vulnerable, dict) or not isinstance(fixed, dict):
        raise ValueError("successful differential needs vulnerable and fixed evidence")
    expected = (vulnerable.get("triggered") is True and
                vulnerable.get("health", {}).get("returncode") == 0 and
                fixed.get("triggered") is False and
                fixed.get("solution", {}).get("returncode") == 0 and
                fixed.get("patched_health", {}).get("returncode") == 0)
    if expected != value["success"] or (value["reward"] == 1.0) != value["success"]:
        raise ValueError("pass2fail verdict contradicts its execution evidence")
    if value["success"] and value.get("status") != "this_bug":
        raise ValueError("successful differential must have status=this_bug")


def execute_verify(profile: Path, output: Path, timeout: int) -> dict[str, Any]:
    """Use the exact exported target/private files, with no intermediate rebuild."""
    started = time.monotonic()
    contract = load_task(profile / "tests/private/task.json")
    submission = profile / "tests/private" / f"reference_{contract['submission_mode']}"
    reward, report = fresh_verify(profile, submission, output,
                                  project="factory" + str(abs(hash(str(output))) % 10**8))
    try:
        validate_report(report)
        valid = True
    except ValueError as exc:
        report["validation_error"] = str(exc)
        valid = False
    return {"status": "passed" if reward == 1.0 and report["success"] and valid else "failed",
            "returncode": 0 if reward == 1.0 and valid else 1, "report": report,
            "elapsed_sec": round(time.monotonic() - started, 2)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    validate_report(json.loads(args.report.read_text(encoding="utf-8")))
    print("pass2fail report schema and differential verdict are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
