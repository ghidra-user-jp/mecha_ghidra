"""build_docker_image.sh --help names the pinned Ghidra version, and still prints without the release file."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None, reason="a bash script")


def _help(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(directory / "build_docker_image.sh"), "--help"], capture_output=True, text=True, timeout=30
    )


def test_help_names_the_version_the_release_file_pins():
    pinned = next(
        line.split("=", 1)[1].strip()
        for line in (ROOT / "scripts" / "ghidra_release.env").read_text(encoding="utf-8").splitlines()
        if line.startswith("MECHA_GHIDRA_GHIDRA_VERSION=")
    )
    result = _help(ROOT)
    assert result.returncode == 0, result.stderr
    assert f"Ghidra {pinned} ZIP" in result.stdout


def test_help_still_prints_without_the_release_file(tmp_path):
    shutil.copy(ROOT / "build_docker_image.sh", tmp_path)
    result = _help(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Ghidra pinned ZIP" in result.stdout
