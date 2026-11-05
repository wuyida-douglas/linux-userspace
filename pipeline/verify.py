#!/usr/bin/env python3
"""Validate differential verifier reports without trusting an exit status alone."""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from .native_agent import stop_process_tree

SAFE_ASAN = "detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=0"


def validate_report(value: Any) -> None:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("report schema_version must be 1")
    if not isinstance(value.get("success"), bool):
        raise ValueError("report.success must be boolean")
    if value.get("branch") not in {"SVC-EXPLOIT", "FILE-EXPLOIT", "FILE-POV"}:
        raise ValueError("report.branch must be a supported delivery route")
    if not isinstance(value.get("host_type"), (str, type(None))):
        raise ValueError("report.host_type must be a string or null")
    expected = {
        "build": "build_returncode",
        "vuln_exploit": "vuln_exploit_returncode",
        "fixed_exploit": "fixed_exploit_returncode",
        "fixed_health": "fixed_health_returncode",
        "benign_control": "benign_returncode",
    }
    for phase, returncode in expected.items():
        evidence = value.get(phase)
        if not isinstance(evidence, dict) or not isinstance(evidence.get("passed"), bool):
            raise ValueError(f"report.{phase} must have boolean passed")
        if not isinstance(evidence.get("output"), str) or not isinstance(evidence.get("command"), str):
            raise ValueError(f"report.{phase} needs command and output")
        if not isinstance(value.get(returncode), int):
            raise ValueError(f"report.{returncode} must be integer")
    success = (value["build"]["passed"] and value["vuln_exploit"]["passed"] and
               not value["fixed_exploit"]["passed"] and value["fixed_health"]["passed"] and
               value["benign_control"]["passed"] and value["build_returncode"] == 0)
    if success != value["success"]:
        raise ValueError("report.success contradicts differential evidence")


def execute_verify(delivery: Path, output: Path, timeout: int, wrapped: bool = False) -> dict[str, Any]:
    """The only orchestrator-run differential, called from final Harbor acceptance."""
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        command = ["bash", str(delivery / "private/verify.sh"),
                   str(delivery.resolve()), str(output.resolve())]
        environment = dict(__import__('os').environ)
        environment["PATH"] = str(Path(__file__).resolve().parents[1] / "config/bin") + ":" + environment.get("PATH", "")
        with (output / "verify.log").open("w", encoding="utf-8") as log:
            environment["ASAN_OPTIONS"] = SAFE_ASAN
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       env=environment, start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_process_tree(process)
                returncode = 124
                log.write(f"\nVerifier timed out after {timeout}s; its process tree was stopped.\n")
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        validate_report(report)
        return {"status": "passed" if returncode == 0 and report["success"] else "failed",
                "returncode": returncode, "report": report,
                "elapsed_sec": round(time.monotonic() - started, 2)}
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return {"status": "error", "failure_class": "pipeline",
                "error": f"{type(exc).__name__}: {exc}",
                "elapsed_sec": round(time.monotonic() - started, 2)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    validate_report(json.loads(args.report.read_text(encoding="utf-8")))
    print("report schema and differential verdict are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
