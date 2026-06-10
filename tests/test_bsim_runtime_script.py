from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_bsim_runtime.sh"


def test_bsim_runtime_validation_script_is_executable_and_env_driven():
    source = SCRIPT.read_text(encoding="utf-8")

    assert os.access(SCRIPT, os.X_OK)
    assert "GHIDRA_BSIM_RUNTIME_VALIDATION=1" in source
    assert "GHIDRA_BSIM_PASSWORD_ENV" in source
    assert "tests/test_runtime_bsim_commands.py -q" in source
