"""Harbor-stable import facade; load the implementation from each task itself.

A single Harbor host process can grade many task profiles. Importing a module
named bin.pass2fail_verifier directly would cache the first task's code. This
facade is common to the bundle and every profile, then dispatches by task_dir.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

from harbor.verifier.base import BaseVerifier


def _implementation(task_dir: Path):
    path = (task_dir / "bin/_pass2fail_verifier.py").resolve()
    if not path.is_file():
        raise FileNotFoundError(f"task-local pass2fail verifier is missing: {path}")
    name = "_linux_userspace_verifier_" + hashlib.sha256(str(path).encode()).hexdigest()[:20]
    import sys
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Pass2FailVerifier(BaseVerifier):
    """Resolve private files on the host, not from the separate container."""

    async def verify(self):
        module = _implementation(Path(self.task.paths.task_dir))
        result = module.fresh_verify(
            Path(self.task.paths.task_dir),
            module.collected_submission(
                Path(self.trial_paths.artifacts_dir),
                module.load_contract(Path(self.task.paths.task_dir))),
            Path(self.trial_paths.verifier_dir),
            "lup" + hashlib.sha256(
                str(self.trial_paths.trial_dir).encode()).hexdigest()[:16],
            timeout_sec=int(self.task.config.verifier.timeout_sec / 2),
        )
        from harbor.models.verifier.result import VerifierResult
        return VerifierResult(rewards={"reward": result[0]})
