"""Fixtures shared by the Ghidra GUI acceptance tests (test_gui_integration.py, test_gui_relay_integration.py)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent


@pytest.fixture(scope="session")
def prepared(tmp_path_factory):
    """One analyzed project and seeded settings, built headlessly once per test session."""
    base = tmp_path_factory.mktemp("gui-prepared")
    project, settings = base / "project", base / "settings"
    completed = subprocess.run(
        [sys.executable, str(TESTS / "gui_project_setup.py"), str(project), str(settings)],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": os.pathsep.join([str(TESTS), str(ROOT / "src")])},
        capture_output=True,
        text=True,
        timeout=600 * float(os.environ.get("GHIDRA_GUI_TEST_TIME_SCALE") or "1"),
    )
    assert completed.returncode == 0, completed.stdout[-4000:] + completed.stderr[-4000:]
    return project, settings
