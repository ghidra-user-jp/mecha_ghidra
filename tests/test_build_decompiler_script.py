from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_decompiler_natives.sh"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-decompiler-natives.yml"


def _run_with_retry_source() -> str:
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"^run_with_retry\(\) \{\n.*?^\}\n", source, re.MULTILINE | re.DOTALL)
    assert match is not None
    return match.group(0)


def test_run_with_retry_preserves_final_failure_status():
    command = (
        "set -euo pipefail\n"
        + _run_with_retry_source()
        + "\nrun_with_retry 2 0 bash -c 'exit 7'\n"
    )

    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 7
    assert "attempt 1/2" in result.stderr


def test_run_with_retry_retries_until_success():
    command = (
        "set -euo pipefail\n"
        + _run_with_retry_source()
        + "\nflaky_calls=0\n"
        + "flaky() { flaky_calls=$((flaky_calls + 1)); [[ ${flaky_calls} -ge 2 ]]; }\n"
        + "run_with_retry 3 0 flaky\n"
        + "printf '%s' \"${flaky_calls}\"\n"
    )

    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == "2"
    assert "attempt 1/3" in result.stderr


def test_linux_release_build_defaults_to_ubuntu_2204_compatible_container():
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'DOCKER_IMAGE="${DOCKER_IMAGE:-eclipse-temurin:21-jdk-jammy}"' in source


def test_release_workflow_checks_ubuntu_2204_and_omits_body_checksums():
    source = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    body_step = source.split("- name: Prepare release body", 1)[1].split(
        "- name: Look up existing release",
        1,
    )[0]

    assert "--docker" in source
    assert "ubuntu:22.04" in source
    assert "SHA-256" not in body_step
    assert "sha256sum" not in body_step
