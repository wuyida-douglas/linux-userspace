"""Resolve the pipeline's Docker CLI wrapper for controller-side commands."""
from __future__ import annotations

from pathlib import Path


def docker_argv(argv: list[str]) -> list[str]:
    """Refresh docker group without escaping the caller's process session."""
    executable = Path(__file__).resolve().parents[1] / "config/bin/docker"
    return [str(executable), *(argv[1:] if argv and argv[0] == "docker" else argv)]