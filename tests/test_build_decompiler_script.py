from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_decompiler_natives.sh"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-decompiler-natives.yml"
RELEASE_ENV = ROOT / "scripts" / "ghidra_release.env"
DOCKERFILE = ROOT / "Dockerfile"


def _run_with_retry_source() -> str:
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"^run_with_retry\(\) \{\n.*?^\}\n", source, re.MULTILINE | re.DOTALL)
    assert match is not None
    return match.group(0)


def test_run_with_retry_preserves_final_failure_status():
    command = "set -euo pipefail\n" + _run_with_retry_source() + "\nrun_with_retry 2 0 bash -c 'exit 7'\n"

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


def test_ghidra_1213_release_builds_all_missing_native_platforms():
    release_env = RELEASE_ENV.read_text(encoding="utf-8")
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "MECHA_GHIDRA_GHIDRA_VERSION=12.1.3" in release_env
    assert "MECHA_GHIDRA_GHIDRA_RELEASE_TAG=Ghidra_12.1.3_build" in release_env
    assert "MECHA_GHIDRA_GHIDRA_DIST_FILENAME=ghidra_12.1.3_PUBLIC_20260817.zip" in release_env
    assert (
        "MECHA_GHIDRA_GHIDRA_DIST_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
        in release_env
    )
    assert "MECHA_GHIDRA_DECOMPILER_NATIVES_RELEASE_TAG=v0.1.5-rc.1" in release_env
    assert "MECHA_GHIDRA_RELEASE_NATIVE_ASSET_RUN_ID=34005839946" in release_env
    assert "MECHA_GHIDRA_RELEASE_NATIVE_ASSET_SOURCE_COMMIT=0e31603" in release_env
    assert (
        "MECHA_GHIDRA_DECOMPILER_NATIVES_SHA256="
        "94d72c80758bc549c01bdbefea52a5ecca2cf54a00b9cecff6e7312892590880" in release_env
    )
    assert (
        "MECHA_GHIDRA_RELEASE_PATCHED_GHIDRA_SHA256="
        "d2c832a60eb080fa0507802057dea037ee75a1f6de2128deee538deeddd0ddd3" in release_env
    )
    assert "Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip" in dockerfile
    assert "v0.1.5-rc.1/ghidra_decompiler_natives_all.zip" in dockerfile
    assert "94d72c80758bc549c01bdbefea52a5ecca2cf54a00b9cecff6e7312892590880" in dockerfile
    assert "github-token: ${{ github.token }}" in workflow
    assert "run-id: ${{ steps.native_asset_source.outputs.run_id }}" in workflow
    assert "Pin tag release to the verified native archives" in workflow

    for platform, runner in (
        ("linux_arm_64", "ubuntu-24.04-arm"),
        ("mac_arm_64", "macos-15"),
        ("mac_x86_64", "macos-15-intel"),
    ):
        assert f"- platform: {platform}" in workflow
        assert f"runs_on: {runner}" in workflow
        assert f"*{platform}_decompiler_overlay.tar.gz" in workflow
        assert f"Ghidra/Features/Decompiler/os/{platform}/decompile" in workflow
        assert f"Ghidra/Features/Decompiler/os/{platform}/sleigh" in workflow
